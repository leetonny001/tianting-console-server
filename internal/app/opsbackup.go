package app

import (
	"context"
	"encoding/json"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"tianting/console/internal/objstore"
)

// CS-116：备份记录（只读）。console-server 的凭证只能列出和读取 manifests/。
//
// 清单的对象键约定（deploy/backup/ 按这个写）：manifests/{source}/{finishedAt 毫秒，补零到 13 位}.json，
// 这样不用读内容就能按时间取最近 48 条。

const (
	backupKeep    = 48
	backupOverdue = 2 * time.Hour
	backupCache   = 30 * time.Second // 总览每 15 秒刷新一次，不用每次都读 96 个对象
)

// backupRecord 只放页面要的字段：路径、桶和凭证都到不了这里。
type backupRecord struct {
	Source           string `json:"source"`
	Trigger          string `json:"trigger"`
	StartedAt        int64  `json:"startedAt"`
	FinishedAt       int64  `json:"finishedAt"`
	File             string `json:"file"`
	Size             int64  `json:"size"`
	SHA256           string `json:"sha256"`
	Verified         bool   `json:"verified"`
	Encrypted        bool   `json:"encrypted"`
	Uploaded         bool   `json:"uploaded"`
	MigrationVersion int    `json:"migrationVersion"`
	Host             string `json:"host"`
	Release          string `json:"release,omitempty"`
	Result           string `json:"result"`
	Error            string `json:"error,omitempty"`
}

type backupGroup struct {
	Source        string         `json:"source"`
	LastSuccessAt int64          `json:"lastSuccessAt"`
	Overdue       bool           `json:"overdue"`
	Records       []backupRecord `json:"records"`
}

type backupData struct {
	Groups []backupGroup `json:"groups"`
}

// sanitize 兜底：清单是脚本写的，但只显示文件名；失败原因摘要里有路径就不显示。
func (r *backupRecord) sanitize() {
	r.File = path.Base(strings.ReplaceAll(r.File, `\`, "/"))
	if strings.ContainsAny(r.Error, `/\`) {
		r.Error = "失败（详情见主机日志）"
	}
}

func (d backupData) withAge(now int64) backupData {
	out := backupData{Groups: make([]backupGroup, 0, len(d.Groups))}
	for _, g := range d.Groups {
		g.Overdue = g.LastSuccessAt == 0 || now-g.LastSuccessAt > backupOverdue.Milliseconds()
		out.Groups = append(out.Groups, g)
	}
	return out
}

// overviewCard 是总览的备份卡片。判断健康只看"最近一次成功"（F-OPS-12 规则 6）。
func (d backupData) overviewCard(now int64) map[string]any {
	groups := d.withAge(now).Groups
	type item struct {
		Source        string `json:"source"`
		LastSuccessAt int64  `json:"lastSuccessAt"`
		Overdue       bool   `json:"overdue"`
	}
	list := make([]item, 0, len(groups))
	for _, g := range groups {
		list = append(list, item{g.Source, g.LastSuccessAt, g.Overdue})
	}
	return map[string]any{"sources": list}
}

type backupCacheEntry struct {
	mu   sync.Mutex
	at   time.Time
	data backupData
}

// backups 读清单，带短缓存（[C 钟]）。
func (a *App) backups(ctx context.Context) (backupData, error) {
	if a.Backups == nil {
		return backupData{}, errBackupNotConfigured
	}
	a.backupCache.mu.Lock()
	defer a.backupCache.mu.Unlock()
	now := a.Clock.Now()
	if !a.backupCache.at.IsZero() && now.Sub(a.backupCache.at) >= 0 && now.Sub(a.backupCache.at) < backupCache {
		return a.backupCache.data, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, err := readBackups(ctx, a.Backups)
	if err != nil {
		return backupData{}, err
	}
	a.backupCache.at, a.backupCache.data = now, d
	return d, nil
}

func readBackups(ctx context.Context, store *objstore.Store) (backupData, error) {
	keys, err := store.List(ctx, "manifests/")
	if err != nil {
		return backupData{}, err
	}
	bySource := map[string][]string{}
	for _, k := range keys {
		parts := strings.Split(k, "/")
		if len(parts) == 3 && strings.HasSuffix(parts[2], ".json") {
			bySource[parts[1]] = append(bySource[parts[1]], k)
		}
	}
	sources := make([]string, 0, len(bySource))
	for s := range bySource {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	out := backupData{Groups: make([]backupGroup, 0, len(sources))}
	for _, s := range sources {
		list := bySource[s]
		sort.Sort(sort.Reverse(sort.StringSlice(list)))
		if len(list) > backupKeep {
			list = list[:backupKeep]
		}
		records := make([]backupRecord, len(list))
		ok := make([]bool, len(list))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for i, k := range list {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				rc, err := store.Get(ctx, k)
				if err != nil {
					return
				}
				defer rc.Close()
				raw, err := io.ReadAll(io.LimitReader(rc, 64<<10))
				if err != nil || json.Unmarshal(raw, &records[i]) != nil {
					return
				}
				ok[i] = true
			}()
		}
		wg.Wait()
		g := backupGroup{Source: s, Records: []backupRecord{}}
		for i := range records {
			if !ok[i] {
				continue // 读不出来的清单跳过：健康只看最近一次成功，少一条不会误判成健康
			}
			r := records[i]
			r.sanitize()
			if r.Source == "" {
				r.Source = s
			}
			if r.Result == "success" && r.FinishedAt > g.LastSuccessAt {
				g.LastSuccessAt = r.FinishedAt
			}
			g.Records = append(g.Records, r)
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

func (c *rc) opsBackups() {
	d, err := c.a.backups(c.ctx)
	if err != nil {
		c.opsOK(cardDown("备份存储"), nil)
		return
	}
	c.opsOK(d.withAge(c.now()), nil)
}
