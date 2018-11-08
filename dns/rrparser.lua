-- LuaJIT FFI bindings for zscanner, a DNS zone parser.
-- Author: Marek Vavrusa <marek@vavrusa.com>

local ffi = require('ffi')
local utils = require('dns.utils')
local kdns = require('dns')
local libzscanner = utils.clib('libzscanner', {1, 2})
assert(libzscanner, 'missing libzscanner1 library')

ffi.cdef[[
void free(void *ptr);
void *realloc(void *ptr, size_t size);

/*
 * Data structures
 */

enum {
	ZS_MAX_RDATA_LENGTH = 65535,
	ZS_MAX_ITEM_LENGTH = 255,
	ZS_MAX_DNAME_LENGTH = 255,
	ZS_MAX_LABEL_LENGTH = 63,
	ZS_MAX_RDATA_ITEMS = 64,
	ZS_BITMAP_WINDOWS = 256,
	ZS_INET4_ADDR_LENGTH = 4,
	ZS_INET6_ADDR_LENGTH = 16,
	ZS_RAGEL_STACK_SIZE = 16,
};

typedef struct zs_state {
	static const int NONE    = 0;
	static const int DATA    = 1;
	static const int ERROR   = 2;
	static const int INCLUDE = 3;
	static const int EOF     = 4;
	static const int STOP    = 5;
} zs_state_t;

/*! \brief Auxiliary structure for storing bitmap window items (see RFC4034). */
typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} zs_win_t;

/*! \brief Auxiliary structure for storing one APL record (see RFC3123). */
typedef struct {
	uint8_t  excl_flag;
	uint16_t addr_family;
	uint8_t  prefix_length;
} zs_apl_t;

/*! \brief Auxiliary structure for storing LOC information (see RFC1876). */
typedef struct {
	uint32_t d1, d2;
	uint32_t m1, m2;
	uint32_t s1, s2;
	uint32_t alt;
	uint64_t siz, hp, vp;
	int8_t   lat_sign, long_sign, alt_sign;
} zs_loc_t;

/*!
 * \brief Context structure for zone scanner.
 *
 * This structure contains following items:
 *  - Copies of Ragel internal variables. The scanner can be called many times
 *    on smaller parts of zone file/memory. So it is necessary to preserve
 *    internal values between subsequent scanner callings.
 *  - Auxiliary variables which are used during processing zone data.
 *  - Pointers to callback functions and pointer to any arbitrary data which
 *    can be used in callback functions.
 *  - Zone file and error information.
 *  - Output variables (r_ prefix) containing all parts of zone record. These
 *    data are useful during processing via callback function.
 */
typedef struct zs_scanner zs_scanner_t; // Forward declaration due to arguments.
struct zs_scanner {
	/*! Current state (Ragel internals). */
	int      cs;
	/*! Stack top (Ragel internals). */
	int      top;
	/*! Call stack (Ragel internals). */
	int      stack[ZS_RAGEL_STACK_SIZE];

	/*! Indicates whether current record is multiline. */
	bool     multiline;
	/*! Auxiliary number for all numeric operations. */
	uint64_t number64;
	/*! Auxiliary variable for time and other numeric operations. */
	uint64_t number64_tmp;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimals;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimal_counter;

	/*! Auxiliary variable for item length (label, base64, ...). */
	uint32_t item_length;
	/*! Auxiliary index for item length position in array. */
	uint32_t item_length_position;
	/*! Auxiliary pointer to item length. */
	uint8_t *item_length_location;
	/*! Auxiliary buffer length. Is zero if no comment after a valid record. */
	uint32_t buffer_length;
	/*! Auxiliary buffer. Contains a comment after a valid record. */
	uint8_t  buffer[ZS_MAX_RDATA_LENGTH];
	/*! Auxiliary buffer for current included file name. */
	char     include_filename[ZS_MAX_RDATA_LENGTH];
	/*! Absolute path for relative includes. */
	char     *path;

	/*! Auxiliary array of bitmap window blocks. */
	zs_win_t windows[ZS_BITMAP_WINDOWS];
	/*! Last window block which is used (-1 means no window). */
	int16_t  last_window;
	/*! Auxiliary apl structure. */
	zs_apl_t apl;
	/*! Auxiliary loc structure. */
	zs_loc_t loc;
	/*! Auxiliary IP address storage. */
	uint8_t  addr[ZS_INET6_ADDR_LENGTH];
	/*! Allow text strings longer than 255 characters. */
	bool     long_string;

	/*! Pointer to the actual dname storage (origin/owner/rdata). */
	uint8_t  *dname;
	/*! Pointer to the actual dname length storage. */
	uint32_t *dname_length;
	/*!
	 * Temporary dname length which is copied to dname_length after
	 * dname processing.
	 */
	uint32_t dname_tmp_length;
	/*! Position of the last free r_data byte. */
	uint32_t r_data_tail;

	/*! Length of the current origin. */
	uint32_t zone_origin_length;
	/*!
	 *  Wire format of the current origin (ORIGIN directive sets this).
	 *
	 * \note Maximal dname length check is after each valid label.
	 */
	uint8_t  zone_origin[ZS_MAX_DNAME_LENGTH + ZS_MAX_LABEL_LENGTH];
	/*! Value of the default class. */
	uint16_t default_class;
	/*! Value of the current default ttl (TTL directive sets this). */
	uint32_t default_ttl;

	/*! The current processing state. */
	int state;

	/*! Processing callbacks and auxiliary data. */
	struct {
		/*! Automatic zone processing using record/error callbacks. */
		bool automatic;
		/*! Callback function for correct zone record. */
		void (*record)(zs_scanner_t *);
		/*! Callback function for wrong situations. */
		void (*error)(zs_scanner_t *);
		/*! Arbitrary data useful inside callback functions. */
		void *data;
	} process;

	/*! Input parameters. */
	struct {
		/*! Start of the block. */
		const char *start;
		/*! Current parser position. */
		const char *current;
		/*! End of the block. */
		const char *end;
		/*! Indication for the final block parsing. */
		bool eof;
		/*! Indication of being mmap()-ed (malloc()-ed otherwise). */
		bool mmaped;
	} input;

	/*! File input parameters. */
	struct {
		/*! Zone file name. */
		char *name;
		/*!< File descriptor. */
		int  descriptor;
	} file;

	struct {
		/*! Last occurred error/warning code. */
		int code;
		/*! Error/warning counter. */
		uint64_t counter;
		/*! Indicates serious error - parsing cannot continue. */
		bool fatal;
	} error;

	/*! Zone data line counter. */
	uint64_t line_counter;

	/*! Length of the current record owner. */
	uint32_t r_owner_length;
	/*!
	 * Owner of the current record.
	 *
	 * \note Maximal dname length check is after each valid label.
	 */
	uint8_t  r_owner[ZS_MAX_DNAME_LENGTH + ZS_MAX_LABEL_LENGTH];
	/*! Class of the current record. */
	uint16_t r_class;
	/*! TTL of the current record. */
	uint32_t r_ttl;
	/*! Type of the current record data. */
	uint16_t r_type;
	/*! Length of the current rdata. */
	uint32_t r_data_length;
	/*! Current rdata. */
	uint8_t  r_data[ZS_MAX_RDATA_LENGTH];

	/*
	 * Example: a. IN 60 MX 1 b. ; A comment
	 *
	 *          r_owner_length = 3
	 *          r_owner = 016100
	 *          r_class = 1
	 *          r_ttl = 60
	 *          r_type = 15
	 *          r_data_length = 5
	 *          r_data = 0001016200
	 *          buffer_length = 11
	 *          buffer = " A comment"
	 */
};

/*
 * Function signatures
 */
int zs_init(zs_scanner_t *scanner, const char *origin, const uint16_t rclass, const uint32_t ttl);
void zs_deinit(zs_scanner_t *scanner);
int zs_set_input_string(zs_scanner_t *scanner, const char *input, size_t size);
int zs_set_input_file(zs_scanner_t *scanner, const char *file_name);
int zs_parse_record(zs_scanner_t *scanner);
const char* zs_strerror(const int code);
]]

-- Constant table
local zs_state = ffi.new('struct zs_state')

-- Sorted set of names
local no_transform = function (x) return x end
local bsearch = utils.bsearch
local flatset_t = ffi.typeof('struct { uint8_t *data; int32_t off[?]; }')
ffi.metatype(flatset_t, {
	__new = function (ct, t, len, bytes)
		local off = 0
		local flat = ffi.new(ct, len)
		flat.data = ffi.C.realloc(nil, bytes)
		for i = 1, len do
			flat.off[i] = off
			local val = t[i]
			local val_len = #val
			ffi.copy(flat.data + off, val.bytes, val_len)
			off = off + val_len
		end
		return flat
	end,
	__gc = function (t)
		ffi.C.free(t.data)
	end,
	__index = function (t, k)
		return kdns.todname(t.data + t.off[k])
	end,
})

local nameset_mt = {
	__index = {
		sort = function (set)
			if set.flat then return end
			table.sort(set.at)
			set.flat = flatset_t(set.at, set.len, set.bytes)
			set.bytes = 0
			set.at = {}
		end,
		search = function (set, owner)
			if not set.flat then error('nameset must be sorted first') end
			return bsearch(set.flat, set.len, owner, nil, no_transform)
		end,
		searcher = function (set)
			if not set.flat then error('nameset must be sorted first') end
			return utils.bsearcher(set.flat, set.len, no_transform)
		end,
		get = function (set, i)
			if not set.flat then error('nameset must be sorted first') end
			if not i or i >= set.len then
				return
			end
			return set.flat[i]
		end,
		put = function (set, value)
			set.bytes = set.bytes + #value
			set.len = set.len + 1
			set.at[set.len] = value:copy()
		end,
	}
}

-- Sorted set of records
local sortedset_t = ffi.typeof('struct { knot_rrset_t *at; int32_t len; int32_t cap; }')
ffi.metatype(sortedset_t, {
	__gc = function (set)
		for i = 0, tonumber(set.len) - 1 do set.at[i]:init(nil, 0) end
		ffi.C.free(set.at)
	end,
	__len = function (set) return tonumber(set.len) end,
	__index = {
		newrr = function (set, noinit)
			-- Reserve enough memory in buffer
			if set.cap == set.len then assert(utils.buffer_grow(set)) end
			local nid = set.len
			set.len = nid + 1
			-- Don't initialize if caller is going to do it immediately
			if not noinit then
				ffi.fill(set.at + nid, ffi.sizeof(set.at[0]))
			end
			return set.at[nid]
		end,
		sort = function (set)
			-- Prefetch RR set comparison function
			return utils.sort(set.at, tonumber(set.len))
		end,
		search = function (set, owner)
			return bsearch(set.at, tonumber(set.len), owner, nil, kdns.rrset.owner)
		end,
		searcher = function (set)
			return utils.bsearcher(set.at, tonumber(set.len), kdns.rrset.owner)
		end,
		get = function (set, i)
			if not i or i >= set.len then
				return
			end
			return set.at[i]
		end,
	}
})

-- Wrap scanner context
local zs_scanner_t = ffi.typeof('struct zs_scanner')
ffi.metatype( zs_scanner_t, {
	__gc = function(zs) libzscanner.zs_deinit(zs) end,
	__new = function(ct, origin, class, ttl)
		if not class then class = 1 end
		if not ttl then ttl = 3600 end
		local parser = ffi.new(ct)
		libzscanner.zs_init(parser, origin, class, ttl)
		return parser
	end,
	__index = {
		open = function (zs, file)
			assert(ffi.istype(zs, zs_scanner_t))
			local ret = libzscanner.zs_set_input_file(zs, file)
			if ret ~= 0 then return false, zs:strerr() end
			return true
		end,
		reset = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			libzscanner.zs_set_input_string(zs, '', 0)
		end,
		parse = function(zs, input)
			assert(ffi.istype(zs, zs_scanner_t))
			if input ~= nil then libzscanner.zs_set_input_string(zs, input, #input) end
			local ret = libzscanner.zs_parse_record(zs)
			-- Return current state only when parsed correctly, otherwise return error
			if ret == 0 and zs.state ~= zs_state.ERROR then
				return zs.state == zs_state.DATA
			else
				return false, zs:strerr()
			end
		end,
		current_rr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return {owner = ffi.string(zs.r_owner, zs.r_owner_length),
			        ttl = tonumber(zs.r_ttl),
			        class = tonumber(zs.r_class),
			        type = tonumber(zs.r_type),
			        rdata = ffi.string(zs.r_data, zs.r_data_length)}
		end,
		strerr = function(zs)
			assert(ffi.istype(zs, zs_scanner_t))
			return ffi.string(libzscanner.zs_strerror(zs.error.code))
		end,
	},
})

-- Module API
local rrparser = {
	new = zs_scanner_t,
	file = function (path)
		local zs = zs_scanner_t()
		local ok, err = zs:open(path)
		if not ok then error(err) end
		local results = {}
		while zs:parse() do
			table.insert(results, zs:current_rr())
		end
		return results
	end,
	state = zs_state,
	set = sortedset_t,
	nameset = function ()
		return setmetatable({at = {}, bytes = 0, len = 0}, nameset_mt)
	end,
}
return rrparser
