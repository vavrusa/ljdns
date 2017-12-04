local ffi = require('ffi')
local utils = require('dns.utils')
local multiflags = require('syscall.helpers').multiflags
local lmdb = utils.clib('lmdb', {0})
if not lmdb then
	lmdb = ffi.load('lmdb')
end

ffi.cdef [[
/*
 * Data structures
 */
typedef struct MDB_env MDB_env;
typedef struct MDB_txn MDB_txn;
typedef unsigned int MDB_dbi;
typedef struct MDB_cursor MDB_cursor;
typedef int MDB_cursor_op;

struct MDB_val {
    size_t size;
    void *data;
};

typedef struct MDB_val MDB_val;

struct MDB_stat {
    unsigned int ms_psize;
    unsigned int ms_depth;
    size_t ms_branch_pages;
    size_t ms_leaf_pages;
    size_t ms_overflow_pages;
    size_t ms_entries;
};
typedef struct MDB_stat MDB_stat;

struct MDB_envinfo {
    void    *me_mapaddr;
    size_t  me_mapsize;
    size_t  me_last_pgno;
    size_t  me_last_txnid;
    unsigned int me_maxreaders;
    unsigned int me_numreaders;
};
typedef struct MDB_envinfo MDB_envinfo;

static const int MDB_SUCCESS =  0;
static const int MDB_KEYEXIST = (-30799);
static const int MDB_NOTFOUND = (-30798);
static const int MDB_PAGE_NOTFOUND = (-30797);
static const int MDB_CORRUPTED = (-30796);
static const int MDB_PANIC = (-30795);
static const int MDB_VERSION_MISMATCH = (-30794);
static const int MDB_INVALID = (-30793);
static const int MDB_MAP_FULL = (-30792);
static const int MDB_DBS_FULL = (-30791);
static const int MDB_READERS_FULL = (-30790);
static const int MDB_TLS_FULL = (-30789);
static const int MDB_TXN_FULL = (-30788);
static const int MDB_CURSOR_FULL = (-30787);
static const int MDB_PAGE_FULL = (-30786);
static const int MDB_MAP_RESIZED = (-30785);
static const int MDB_INCOMPATIBLE = (-30784);
static const int MDB_BAD_RSLOT = (-30783);
static const int MDB_BAD_TXN = (-30782);
static const int MDB_BAD_VALSIZE = (-30781);
static const int MDB_LAST_ERRCODE = MDB_BAD_VALSIZE;

/*
 * Wrapper structures for opaque objects.
 */
struct mdb_envref_t {
    MDB_env *env;
};

struct mdb_txnref_t {
    struct MDB_txn *txn;
    MDB_dbi dbi;
    bool valid;
};

struct mdb_cursorref_t {
    struct MDB_cursor *c;
    MDB_dbi dbi;
};

/*
 * Public functions
 */
char *mdb_version(int *major, int *minor, int *patch);
char *mdb_strerror(int err);
int  mdb_env_create(MDB_env **env);
int  mdb_env_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode);
int  mdb_env_copy(MDB_env *env, const char *path);
int  mdb_env_stat(MDB_env *env, MDB_stat *stat);
int  mdb_env_info(MDB_env *env, MDB_envinfo *stat);
int  mdb_env_sync(MDB_env *env, int force);
void mdb_env_close(MDB_env *env);
int  mdb_env_set_flags(MDB_env *env, unsigned int flags, int onoff);
int  mdb_env_get_flags(MDB_env *env, unsigned int *flags);
int  mdb_env_get_path(MDB_env *env, const char **path);
int  mdb_env_set_mapsize(MDB_env *env, size_t size);
int  mdb_env_set_maxreaders(MDB_env *env, unsigned int readers);
int  mdb_env_get_maxreaders(MDB_env *env, unsigned int *readers);
int  mdb_env_set_maxdbs(MDB_env *env, MDB_dbi dbs);

int  mdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn);
int  mdb_txn_commit(MDB_txn *txn);
void mdb_txn_abort(MDB_txn *txn);
void mdb_txn_reset(MDB_txn *txn);
int  mdb_txn_renew(MDB_txn *txn);
int  mdb_dbi_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi);
int  mdb_stat(MDB_txn *txn, MDB_dbi dbi, MDB_stat *stat);
void mdb_dbi_close(MDB_env *env, MDB_dbi dbi);
int  mdb_drop(MDB_txn *txn, MDB_dbi dbi, int del);
int  mdb_get(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data);
int  mdb_put(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data,
             unsigned int flags);
int  mdb_del(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data);

int  mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **cursor);
void mdb_cursor_close(MDB_cursor *cursor);
int  mdb_cursor_renew(MDB_txn *txn, MDB_cursor *cursor);

MDB_txn *mdb_cursor_txn(MDB_cursor *cursor);
MDB_dbi mdb_cursor_dbi(MDB_cursor *cursor);

int  mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
                    MDB_cursor_op op);
int  mdb_cursor_put(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
                    unsigned int flags);
int  mdb_cursor_del(MDB_cursor *cursor, unsigned int flags);
int  mdb_cursor_count(MDB_cursor *cursor, size_t *countp);
]]

-- Flag tables
local mdb_env_flags = multiflags {
    FIXEDMAP = 0x01,
    NOSUBDIR = 0x4000,
    NOSYNC = 0x10000,
    RDONLY = 0x20000,
    NOMETASYNC = 0x40000,
    WRITEMAP = 0x80000,
    MAPASYNC = 0x100000,
    NOTLS = 0x200000,
    NOLOCK = 0x400000,
    NORDAHEAD = 0x800000,
    NOMEMINIT = 0x1000000,
}

local mdb_open_flags = multiflags {
    REVERSEKEY = 0x02,
    DUPSORT = 0x04,
    INTEGERKEY = 0x08,
    DUPFIXED = 0x10,
    INTEGERDUP = 0x20,
    REVERSEDUP = 0x40,
    CREATE = 0x40000,
}

local mdb_put_flags = multiflags {
    NOOVERWRITE = 0x10,
    NODUPDATA = 0x20,
    CURRENT = 0x40,
    RESERVE = 0x10000,
    APPEND = 0x20000,
    APPENDDUP = 0x40000,
    MULTIPLE = 0x80000,
}

local mdb_cursor_op = {
    FIRST          = 0,
    FIRST_DUP      = 1,
    GET_BOTH       = 2,
    GET_BOTH_RANGE = 3,
    GET_CURRENT    = 4,
    GET_MULTIPLE   = 5,
    LAST           = 6,
    LAST_DUP       = 7,
    NEXT           = 8,
    NEXT_DUP       = 9,
    NEXT_MULTIPLE  = 10,
    NEXT_NODUP     = 11,
    PREV           = 12,
    PREV_DUP       = 13,
    PREV_NODUP     = 14,
    SET            = 15,
    SET_KEY        = 16,
    SET_RANGE      = 17,
}

-- Export module
local M = {op = mdb_cursor_op}

-- Helpers
local function toerror(ret)
    return nil, ffi.string(lmdb.mdb_strerror(ret))
end

-- Metatype for MDB key/value
local mdb_val_t = ffi.typeof('struct MDB_val')
ffi.metatype(mdb_val_t, {
    __tostring = function (self)
        return ffi.string(self.data, self.size)
    end,
    __len = function (self)
        return tonumber(self.size)
    end,
})
M.val_t = mdb_val_t

-- Wrapper for cursor
local mdb_cursor_t = ffi.typeof('struct mdb_cursorref_t')
ffi.metatype(mdb_cursor_t, {
    __gc = function (t)
        t:close()
    end,
    __index = {
        close = function (t)
            if t.c ~= nil then
                lmdb.mdb_cursor_close(t.c)
                t.c = nil
            end
        end,
        next = function (t, k, v, op)
            assert(t.c ~= nil, 'cursor operation on dead cursor')
            if k then
                op = op or mdb_cursor_op.NEXT
            else
                k = mdb_val_t()
                op = op or mdb_cursor_op.FIRST
            end
            -- Set cursor to next iteration
            v = v or mdb_val_t()
            local ret = lmdb.mdb_cursor_get(t.c, k, v, op)
            if ret == lmdb.MDB_NOTFOUND then
                return nil
            elseif ret ~= 0 then
                return toerror(ret)
            end
            return k, v
        end,
        prev = function (t, k, v)
            return t:next(k, v, mdb_cursor_op.PREV)
        end,
        seek = function (t, k, v, op)
            assert(t.c ~= nil, 'cursor operation on dead cursor')
            v = v or mdb_val_t()
            local ret = lmdb.mdb_cursor_get(t.c, k, v, op or mdb_cursor_op.SET_RANGE)
            if ret == lmdb.MDB_NOTFOUND then
                return nil
            elseif ret ~= 0 then
                return toerror(ret)
            end
            return k, v
        end,
    },
    __ipairs = function(t)
        return t.next, t, nil
    end
})

-- Wrapper for transaction object as MDB transaction is opaque
local mdb_txn_t = ffi.typeof('struct mdb_txnref_t')
ffi.metatype(mdb_txn_t, {
    __gc = function (t)
        if t.valid then t:abort() end
    end,
    __index = {
        abort = function (t)
            assert(t.valid, 'operation on aborted transaction')
            lmdb.mdb_txn_abort(t.txn)
            t.valid = false
        end,
        commit = function (t)
            assert(t.valid, 'operation on aborted transaction')
            local ret = lmdb.mdb_txn_commit(t.txn)
            t.valid = false
            if ret ~= 0 then return toerror(ret) end
            return true
        end,
        reset = function (t)
            assert(t.valid, 'operation on aborted transaction')
            lmdb.mdb_txn_reset(t.txn)
            t.valid = false
        end,
        renew = function (t)
            assert(not t.valid, 'cannot renew valid transaction')
            local ret = lmdb.mdb_txn_renew(t.txn)
            t.valid = true
            if ret ~= 0 then return toerror(ret) end
            return true
        end,
        put = function (t, key, val, flags)
            assert(t.valid, 'operation on aborted transaction')
            if not ffi.istype(mdb_val_t, key) then key = mdb_val_t(#key, ffi.cast('void *', key)) end
            if not ffi.istype(mdb_val_t, val) then val = mdb_val_t(#val, ffi.cast('void *', val)) end
            local ret = lmdb.mdb_put(t.txn, t.dbi, key, val, mdb_put_flags[flags or 0])
            if ret == lmdb.MDB_KEYEXIST then
                return false
            elseif ret ~= 0 then
                return toerror(ret)
            end
            return true
        end,
        get = function (t, key, val)
            assert(t.valid, 'operation on aborted transaction')
            if type(key) == 'string' then key = mdb_val_t(#key, ffi.cast('void *', key)) end
            if not val then val =  mdb_val_t() end
            local ret = lmdb.mdb_get(t.txn, t.dbi, key, val)
            if ret == lmdb.MDB_NOTFOUND then
                return nil
            elseif ret ~= 0 then
                return toerror(ret)
            end
            return val, key
        end,
        del = function (t, key, val)
            assert(t.valid, 'operation on aborted transaction')
            if type(key) == 'string' then key = mdb_val_t(#key, ffi.cast('void *', key)) end
            if not val then val =  mdb_val_t() end
            local ret = lmdb.mdb_del(t.txn, t.dbi, key, val)
            if ret ~= 0 then return toerror(ret) end
            return true
        end,
        cursor = function (t)
            local cursor = ffi.new('MDB_cursor *[1]')
            local ret = lmdb.mdb_cursor_open(t.txn, t.dbi, cursor)
            if ret ~= 0 then return toerror(ret) end
            return mdb_cursor_t(cursor[0], t.dbi)
        end
    },
})

-- Wrapper for MDB environment
local mdb_env_t = ffi.typeof('struct mdb_envref_t')
ffi.metatype(mdb_env_t, {
    __gc = function(t)
        t:close()
    end,
    __index = {
        path = function (t)
            local path = ffi.new('const char* [1]')
            local ret = lmdb.mdb_env_get_path(t.env, path)
            if ret ~= 0 then return toerror(ret) end
            return ffi.string(path[0])
        end,
        copy = function (t, dst_path)
            if not dst_path then return nil end
            local ret = lmdb.mdb_env_copy(t.env, dst_path)
            if ret ~= 0 then return toerror(ret) end
            return ret
        end,
        txn = function (t, dbi, flags, parent)
            flags = mdb_env_flags[flags or 0]
            dbi = dbi or 0
            local txn = ffi.new('MDB_txn* [1]')
            local ret = lmdb.mdb_txn_begin(t.env, parent, flags, txn)
            if ret ~= 0 then return toerror(ret) end
            return mdb_txn_t(txn[0], dbi, true)
        end,
        open = function (t, name, flags, txn)
            flags = mdb_open_flags[flags or 0]
            txn = txn or t:txn(flags)
            local dbi = ffi.new('MDB_dbi [1]')
            local ret = lmdb.mdb_dbi_open(txn.txn, name, flags, dbi)
            if ret ~= 0 then return toerror(ret) end
            txn.dbi = dbi[0]
            return txn, dbi[0]
        end,
        close = function (t)
            if t.env ~= nil then
                lmdb.mdb_env_close(t.env)
                t.env = nil
            end
        end,
        stat = function (t)
            local stat = ffi.new('MDB_stat [1]')
            local ret = lmdb.mdb_env_stat(t.env, stat)
            if ret ~= 0 then return toerror(ret) end
            return stat[0]
        end
    }
})

-- Export module interface
function M.version()
    local version = ffi.new('int [3]')
    lmdb.mdb_version(version, version+1, version+2)
    return version[0], version[1], version[2]
end

function M.open(path, flags, size, mode, maxdbs)
    assert(path, 'cannot open env without path')
    flags = mdb_env_flags[flags or 0]
    size = size or 100*1024*1024
    -- Create database environment
    local env = ffi.new('MDB_env *[1]')
    local ret = lmdb.mdb_env_create(env)
    if ret ~= 0 then return toerror(ret) end
    env = mdb_env_t(env[0])
    if maxdbs then
        ret = lmdb.mdb_env_set_maxdbs(env.env, maxdbs)
        if ret ~= 0 then return toerror(ret) end
    end
    ret = lmdb.mdb_env_set_mapsize(env.env, size)
    if ret ~= 0 then return toerror(ret) end
    -- Open the environment
    ret = lmdb.mdb_env_open(env.env, path, mdb_env_flags[flags or 0], tonumber(mode or 660, 8))
    if ret ~= 0 then return toerror(ret) end
    return env
end

return M
