-- LuaJIT ffi bindings for zscanner, a DNS zone parser.
-- Author: Marek Vavrusa <marek.vavrusa@nic.cz>
--

local ffi = require('ffi')
local utils = require('kdns.utils')
local libzscanner = ffi.load(utils.dll_versioned('libzscanner', '0'))
ffi.cdef[[
int memcmp(const void *s1, const void *s2, size_t n);

/*
 * POSIX I/O
 */
typedef struct {} FILE;
size_t fread(void *ptr, size_t size, size_t count, FILE *stream);
FILE *fopen(const char *filename, const char * mode);
int feof(FILE * stream);
int fclose(FILE * stream);

/*
 * Data structures
 */

enum {
	MAX_RDATA_LENGTH = 65535,
	MAX_ITEM_LENGTH = 255,
	MAX_DNAME_LENGTH = 255,
	MAX_LABEL_LENGTH = 63,
	MAX_RDATA_ITEMS = 64,
	BITMAP_WINDOWS = 256,
	INET4_ADDR_LENGTH = 4,
	INET6_ADDR_LENGTH = 16,
	RAGEL_STACK_SIZE = 16,
};
typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} window_t;
typedef struct {
	uint8_t  excl_flag;
	uint16_t addr_family;
	uint8_t  prefix_length;
} apl_t;
typedef struct {
	uint32_t d1, d2;
	uint32_t m1, m2;
	uint32_t s1, s2;
	uint32_t alt;
	uint64_t siz, hp, vp;
	int8_t   lat_sign, long_sign, alt_sign;
} loc_t;

typedef struct scanner zs_scanner_t;
struct scanner {
	int      cs;
	int      top;
	int      stack[RAGEL_STACK_SIZE];
	bool     multiline;
	uint64_t number64;
	uint64_t number64_tmp;
	uint32_t decimals;
	uint32_t decimal_counter;
	uint32_t item_length;
	uint32_t item_length_position;
	uint8_t *item_length_location;
	uint32_t buffer_length;
	uint8_t  buffer[MAX_RDATA_LENGTH];
	char     include_filename[MAX_RDATA_LENGTH + 1];
	window_t windows[BITMAP_WINDOWS];
	int16_t  last_window;
	apl_t    apl;
	loc_t    loc;
	bool     long_string;
	uint8_t  *dname;
	uint32_t *dname_length;
	uint32_t dname_tmp_length;
	uint32_t r_data_tail;
	uint32_t zone_origin_length;
	uint8_t  zone_origin[MAX_DNAME_LENGTH + MAX_LABEL_LENGTH];
	uint16_t default_class;
	uint32_t default_ttl;
	void (*process_record)(zs_scanner_t *);
	void (*process_error)(zs_scanner_t *);
	void     *data;
	char     *path;
	uint64_t line_counter;
	int      error_code;
	uint64_t error_counter;
	bool     stop;
	struct {
		char *name;
		int  descriptor;
	} file;
	uint32_t r_owner_length;
	uint8_t  r_owner[MAX_DNAME_LENGTH + MAX_LABEL_LENGTH];
	uint16_t r_class;
	uint32_t r_ttl;
	uint16_t r_type;
	uint32_t r_data_length;
	uint8_t  r_data[MAX_RDATA_LENGTH];
};

/*
 * Function signatures
 */

zs_scanner_t* zs_scanner_create(const char     *origin,
                                const uint16_t rclass,
                                const uint32_t ttl,
                                void (*process_record)(zs_scanner_t *),
                                void (*process_error)(zs_scanner_t *),
                                void *data);
void zs_scanner_free(zs_scanner_t *scanner);
int zs_scanner_parse(zs_scanner_t *scanner,
                     const char   *start,
                     const char   *end,
                     const bool   final_block);
int zs_scanner_parse_file(zs_scanner_t *scanner,
                          const char   *file_name);
const char* zs_strerror(const int code);
]]

-- LuaJIT 2.1 has table.clear
local ok, table_clear = pcall(require, 'table.clear')
if not ok then
	table_clear = function (table)
		for i, v in ipairs(table) do table[i] = nil end
	end
end

-- Wrap scanner context
local const_char_t = ffi.typeof('const char *')
local zs_scanner_t = ffi.typeof('zs_scanner_t')
ffi.metatype( zs_scanner_t, {
	__new = function(zs, on_record, on_error)
		return ffi.gc(libzscanner.zs_scanner_create('.', 1, 3600, on_record, on_error, nil),
		              libzscanner.zs_scanner_free)
	end,
	__index = {
		parse_file = function(zs, file)
			return libzscanner.zs_scanner_parse_file(zs, file)
		end,
		read = function(zs, str, len)
			if not len then len = #str end
			local buf = ffi.cast(const_char_t, str)
			return libzscanner.zs_scanner_parse(zs, buf, buf + len, false)
		end,
		current_rr = function(zs)
			return {owner = ffi.string(zs.r_owner, zs.r_owner_length),
			        ttl = tonumber(zs.r_ttl),
			        class = tonumber(zs.r_class),
			        type = tonumber(zs.r_type), 
			        rdata = ffi.string(zs.r_data, zs.r_data_length)}
		end,
		last_error = function(zs)
			return ffi.string(libzscanner.zs_strerror(zs.error_code))
		end,
	},
})

-- POSIX I/O
local fbuflen = 2^15
local fbuf = ffi.new('char[?]', fbuflen)
local file_t = ffi.typeof('FILE')
local function file_close(fp) ffi.C.fclose(fp) end
ffi.metatype( file_t, {
	__new = function (ct, path, mode) return ffi.gc(ffi.C.fopen(path, mode), file_close) end,
	__index = {
		read = function (fp, buf, buflen)
			if ffi.C.feof(fp) ~= 0 then return 0 end
			return ffi.C.fread(buf, 1, buflen, fp)
		end,
	}
})

local function stream_consume(parser, fs)
	local rb = fs:read(fbuf, fbuflen)
	if rb > 0 then
		return parser:read(fbuf, fbuflen) == 0
	else return false end
end

-- Stream parser that generates RRs
local function stream_parser(path)
	local fs = file_t(path, 'r')
	if not fs then return nil end
	local rrbufs, avail, cur = {}, 0, 0
	local parser = zs_scanner_t(function (p)
		table.insert(rrbufs, p:current_rr())
		avail = avail + 1
	end)
	return function ()
		while avail == 0 do
			table_clear(rrbufs)
			if not stream_consume(parser, fs) then
				return false
			end
			cur = 0
		end
		avail = avail - 1
		cur = cur + 1
		return rrbufs[cur]
	end
end

-- Module API
local rrparser = {
	new = zs_scanner_t,
	parse_file = function (path)
		local records = {}
		local parser = zs_scanner_t(function (parser)
			table.insert(records, parser:current_rr())
		end)
		if parser:parse_file(path) ~= 0 then
			return nil
		end
		return records
	end,
	stream = stream_parser,
}
return rrparser
