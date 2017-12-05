local ffi = require('ffi')

ffi.cdef[[
/* libc */
char *strdup(const char *s);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
int memcmp(const void *a, const void *b, size_t len);

/*
 * Data structures
 */
typedef uint8_t knot_rdata_t;
typedef struct {
	bool	wrap;
	bool	show_class;
	bool	show_ttl;
	bool	verbose;
	bool	empty_ttl;
	bool	human_ttl;
	bool	human_tmstamp;
	bool	generic;
	void (*ascii_to_idn)(char **name);
} knot_dump_style_t;
typedef int knot_section_t; /* Do not touch */
typedef void knot_rrinfo_t; /* Do not touch */
typedef struct knot_dname { uint8_t bytes[?]; } knot_dname_t;
typedef struct knot_rdataset knot_rdataset_t;
struct knot_rdataset {
	uint16_t rr_count;
	knot_rdata_t *data;
};
typedef struct knot_rrset {
	knot_dname_t *_owner; /* This is private because GC-unaware */
	uint16_t _type;
	uint16_t rclass;
	knot_rdataset_t rrs;
} knot_rrset_t;
typedef struct {
	struct knot_pkt *pkt;
	uint16_t pos;
	uint16_t count;
} knot_pktsection_t;
typedef struct {
	uint8_t *wire;
	size_t size;
	size_t max_size;
	size_t parsed;
	uint16_t reserved;
	uint16_t qname_size;
	uint16_t rrset_count;
	uint16_t flags;
	knot_rrset_t *opt_rr;
	knot_rrset_t *tsig_rr;
	struct {
		uint8_t *pos;
		size_t len;
	} _tsig_wire;
	knot_section_t cur_section;
	knot_pktsection_t _sections[3];
	size_t _rrset_allocd;
	knot_rrinfo_t *_rr_info;
	knot_rrset_t *_rr;
	uint8_t _stub[]; /* Do not touch */
} knot_pkt_t;
typedef struct {
	size_t size;
	uint8_t *data;
} dnssec_binary_t;
typedef struct {
	int algorithm;
	knot_dname_t *name;
	dnssec_binary_t secret;
} knot_tsig_key_t;
/* descriptors */
const char *knot_strerror(int code);
int knot_rrtype_to_string(uint16_t rrtype, char *out, size_t out_len);
/* domain names */
int knot_dname_size(const knot_dname_t *name);
int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2);
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen);
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen);
int knot_dname_to_lower(knot_dname_t *name);
int knot_dname_labels(const knot_dname_t *name, const knot_dname_t *pkt);
bool knot_dname_in(const knot_dname_t *domain, const knot_dname_t *sub);
knot_dname_t *knot_dname_copy(const void *name, void /* mm_ctx_t */ *mm);
int knot_dname_unpack(uint8_t *dst, const knot_dname_t *src, size_t maxlen, const uint8_t *pkt);
/* resource records */
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
uint16_t knot_rdata_rdlen(void *rr);
uint8_t *knot_rdata_data(void *rr);
size_t knot_rdata_array_size(uint16_t size);
uint32_t knot_rdata_ttl(const knot_rdata_t *rr);
void knot_rdata_set_ttl(knot_rdata_t *rr, uint32_t ttl);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, size_t pos);
int knot_rrset_txt_dump(const knot_rrset_t *rrset, char **dst, size_t *maxlen, const knot_dump_style_t *style);
int knot_rrset_txt_dump_data(const knot_rrset_t *rrset, size_t pos, char *dst, size_t maxlen, const knot_dump_style_t *style);
int knot_rrset_add_rdata(knot_rrset_t *rrset, const uint8_t *rdata, const uint16_t size, const uint32_t ttl, void *mm);
/* opt rr */
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr);
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version);
int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code, uint16_t length, const uint8_t *data, void *mm);
bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code);
uint8_t *knot_edns_get_option(const knot_rrset_t *opt_rr, uint16_t code);
uint16_t knot_edns_opt_get_length(const uint8_t *opt);
size_t knot_edns_wire_size(knot_rrset_t *opt_rr);
void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode);
uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr);
/* packet */
knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt);
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt);
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt);
int knot_pkt_begin(knot_pkt_t *pkt, int section_id);
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section, uint16_t i);
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt, knot_section_t section_id);
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, /* mm_ctx_t */ void *mm);
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr, uint16_t flags);
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t qclass, uint16_t qtype);
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_question(knot_pkt_t *pkt);
void knot_pkt_clear(knot_pkt_t *pkt);
void knot_pkt_free(knot_pkt_t **pkt);
/* tsig */
int knot_tsig_key_init_str(knot_tsig_key_t *key, const char *params);
int knot_tsig_key_init_file(knot_tsig_key_t *key, const char *filename);
int knot_tsig_key_copy(knot_tsig_key_t *dst, const knot_tsig_key_t *src);
void knot_tsig_key_deinit(knot_tsig_key_t *key);
int knot_tsig_sign(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                   const uint8_t *request_mac, size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_tsig_key_t *key, uint16_t tsig_rcode,
                   uint64_t request_time_signed);
int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_tsig_key_t *key,
                           uint64_t prev_time_signed);
const uint8_t *knot_tsig_rdata_mac(const knot_rrset_t *tsig);
size_t knot_tsig_rdata_mac_length(const knot_rrset_t *tsig);
uint64_t knot_tsig_rdata_time_signed(const knot_rrset_t *tsig);
]]