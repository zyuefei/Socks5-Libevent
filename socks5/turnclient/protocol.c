/**
 * \file protocol.c
 * \author hong.he
 * \date 2012-2013
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <pjlib-util/hmac_sha1.h>

// #include <openssl/evp.h>
// #include <openssl/hmac.h>

#include "util_sys.h"
#include "util_crypto.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C"
{
/* } */
#endif

/**
 * \brief Helper function to create MAPPED-ADDRESS like.
 * \param type type
 * \param address network address
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
static struct turn_attr_hdr* turn_attr_address_create(uint16_t type, const struct sockaddr* address, struct iovec* iov) {
    /* MAPPED-ADDRESS are the same as ALTERNATE-ADDRESS */
    struct turn_attr_mapped_address* ret = NULL;
    size_t len = 0;
    uint8_t* ptr = NULL; /* pointer on the address (IPv4 or IPv6) */
    uint8_t family = 0;
    uint16_t port = 0;

    switch(address->sa_family) {
    case AF_INET:
        ptr = (uint8_t*)&((struct sockaddr_in*)address)->sin_addr;
        port = ntohs(((struct sockaddr_in*)address)->sin_port);
        family = STUN_ATTR_FAMILY_IPV4;
        len = 4;
        break;
#if 0
    case AF_INET6:
        if(IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)address)->sin6_addr)) {
            ptr = &((struct sockaddr_in6*)address)->sin6_addr.s6_addr[12];
            port = ((struct sockaddr_in6*)&address)->sin6_port;
            family = STUN_ATTR_FAMILY_IPV4;
            len = 4;
        } else {
            ptr = (uint8_t*)&((struct sockaddr_in6*)address)->sin6_addr;
            port = ntohs(((struct sockaddr_in6*)address)->sin6_port);
            family = STUN_ATTR_FAMILY_IPV6;
            len = 16;
            break;
        }
#endif
    default:
        return NULL;
        break;
    }

    if(!(ret = malloc(sizeof(struct turn_attr_mapped_address) + len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(type);
    /* reserved (1)  + family (1) + port (2) + address (variable) */
    ret->turn_attr_len = htons(4 + len);
    ret->turn_attr_reserved = 0;
    ret->turn_attr_family = family;
    ret->turn_attr_port = htons(port);
    memcpy(ret->turn_attr_address, ptr, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_mapped_address) + len;

    return (struct turn_attr_hdr*)ret;
}

/**
 * \brief Helper function to create XOR-MAPPED-ADDRESS like.
 * \param type type
 * \param address network address
 * \param cookie magic cookie
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
static struct turn_attr_hdr* turn_attr_xor_address_create(uint16_t type, const struct sockaddr* address, uint32_t cookie, const uint8_t* id, struct iovec* iov) {
    /* XOR-MAPPED-ADDRESS are the same as XOR-PEER-ADDRESS and
     * XOR-RELAYED-ADDRESS
     */
    struct turn_attr_xor_mapped_address* ret = NULL;
    size_t len = 0;
    uint8_t* ptr = NULL; /* pointer on the address (IPv4 or IPv6) */
    uint8_t* p = (uint8_t*)&cookie;
    size_t i = 0;
    struct sockaddr_storage storage;
    uint16_t port = 0;
    uint8_t family = 0;
    uint16_t msb_cookie = 0;

    switch(address->sa_family) {
    case AF_INET:
        memcpy(&storage, address, sizeof(struct sockaddr_in));
        ptr = (uint8_t*)&((struct sockaddr_in*)&storage)->sin_addr;
        port = ntohs(((struct sockaddr_in*)&storage)->sin_port);
        family = STUN_ATTR_FAMILY_IPV4;
        len = 4;
        break;
#if 0
    case AF_INET6:
        if(IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)address)->sin6_addr)) {
            ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
            memcpy(&((struct sockaddr_in*)&storage)->sin_addr,
                   &((struct sockaddr_in6*)address)->sin6_addr.s6_addr[12], 4);
            ptr = (uint8_t*)&((struct sockaddr_in*)&storage)->sin_addr;
            ((struct sockaddr_in*)&storage)->sin_port =
                ((struct sockaddr_in6*)address)->sin6_port;
            memset(((struct sockaddr_in*)&storage)->sin_zero, 0x00,
                   sizeof(((struct sockaddr_in*)&storage)->sin_zero));
            port = ntohs(((struct sockaddr_in*)&storage)->sin_port);
            family = STUN_ATTR_FAMILY_IPV4;
            len = 4;
        } else {
            memcpy(&storage, address, sizeof(struct sockaddr_in6));
            ptr = (uint8_t*)&((struct sockaddr_in6*)&storage)->sin6_addr;
            port = ntohs(((struct sockaddr_in6*)&storage)->sin6_port);
            family = STUN_ATTR_FAMILY_IPV6;
            len = 16;
        }
        break;
#endif
    default:
        return NULL;
        break;
    }

    if(!(ret = malloc(sizeof(struct turn_attr_xor_mapped_address) + len))) {
        return NULL;
    }

    /* XOR the address and port */

    /* host order port XOR most-significant 16 bits of the cookie */
    cookie = htonl(cookie);
    msb_cookie = ((uint8_t*)&cookie)[0] << 8 | ((uint8_t*)&cookie)[1];
    port ^= msb_cookie;

    /* IPv4/IPv6 XOR cookie (just the first four bytes of IPv6 address) */
    for(i = 0 ; i < 4 ; i++) {
        ptr[i] ^= p[i];
    }

    /* end of IPv6 address XOR transaction ID */
    for(i = 4 ; i < len ; i++) {
        ptr[i] ^= id[i - 4];
    }

    ret->turn_attr_type = htons(type);
    /* reserved (1)  + family (1) + port (2) + address (variable) */
    ret->turn_attr_len = htons(4 + len);
    ret->turn_attr_reserved = 0;
    ret->turn_attr_family = family;
    ret->turn_attr_port = htons(port);
    memcpy(ret->turn_attr_address, ptr, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_xor_mapped_address) + len;

    return (struct turn_attr_hdr*)ret;
}

struct turn_msg_hdr* turn_msg_create(uint16_t type, uint16_t len, const uint8_t* id, struct iovec* iov) {
    struct turn_msg_hdr* ret = NULL;

    if((ret = malloc(sizeof(struct turn_msg_hdr))) == NULL) {
        return NULL;
    }

    ret->turn_msg_type = htons(type);
    ret->turn_msg_len = htons(len);
    ret->turn_msg_cookie = htonl(STUN_MAGIC_COOKIE);
    memcpy(ret->turn_msg_id, id, 12);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_msg_hdr);

    return ret;
}

struct turn_attr_hdr* turn_attr_create(uint16_t type, uint16_t len, struct iovec* iov, const void* data) {
    struct turn_attr_hdr* ret = NULL;

    if((ret = malloc(sizeof(struct turn_attr_hdr) + len)) == NULL) {
        return NULL;
    }

    ret->turn_attr_type = htons(type);
    ret->turn_attr_len = htons(len);
    memcpy(ret->turn_attr_value, data, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_hdr) + len;

    return ret;
}

/* STUN messages */

struct turn_msg_hdr* turn_msg_binding_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((STUN_METHOD_BINDING | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_binding_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((STUN_METHOD_BINDING | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_binding_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((STUN_METHOD_BINDING | STUN_ERROR_RESP), len, id, iov);
}

/* TURN messages */

struct turn_msg_hdr* turn_msg_allocate_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_ALLOCATE | STUN_REQUEST) , len, id, iov);
}

struct turn_msg_hdr* turn_msg_allocate_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_ALLOCATE | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_allocate_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_ALLOCATE | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_send_indication_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_SEND | STUN_INDICATION), len, id, iov);
}

struct turn_msg_hdr* turn_msg_data_indication_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_DATA | STUN_INDICATION), len, id, iov);
}

struct turn_msg_hdr* turn_msg_refresh_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_REFRESH | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_refresh_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_REFRESH | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_refresh_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_REFRESH | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_createpermission_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CREATEPERMISSION | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_createpermission_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CREATEPERMISSION | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_createpermission_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CREATEPERMISSION | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_channelbind_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CHANNELBIND | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_channelbind_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CHANNELBIND | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_channelbind_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CHANNELBIND | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connect_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECT | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connect_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECT | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connect_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECT | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connectionbind_request_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECTIONBIND | STUN_REQUEST), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connectionbind_response_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECTIONBIND | STUN_SUCCESS_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connectionbind_error_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECTIONBIND | STUN_ERROR_RESP), len, id, iov);
}

struct turn_msg_hdr* turn_msg_connectionattempt_indication_create(uint16_t len, const uint8_t* id, struct iovec* iov) {
    return turn_msg_create((TURN_METHOD_CONNECTIONATTEMPT | STUN_INDICATION), len, id, iov);
}
/* STUN attributes */

struct turn_attr_hdr* turn_attr_mapped_address_create(const struct sockaddr* address, struct iovec* iov) {
    return turn_attr_address_create(STUN_ATTR_MAPPED_ADDRESS, address, iov);
}

struct turn_attr_hdr* turn_attr_username_create(const char* username, size_t len, struct iovec* iov) {
    struct turn_attr_username* ret = NULL;
    size_t real_len = len;

    /* MUST be less than 513 bytes */
    if(len >= 513) {
        return NULL;
    }

    /* real_len, attribute header size and padding must be a multiple of four */
    if((real_len + 4) % 4) {
        real_len += (4 - (real_len % 4));
    }

    if(!(ret = malloc(sizeof(struct turn_attr_username) + real_len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_USERNAME);
    ret->turn_attr_len = htons(len);
    memset(ret->turn_attr_username, 0x00, real_len);
    memcpy(ret->turn_attr_username, username, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_username) + real_len;

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_message_integrity_create(const uint8_t* hmac, struct iovec* iov) {
    struct turn_attr_message_integrity* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_message_integrity)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_MESSAGE_INTEGRITY);
    ret->turn_attr_len = htons(20);

    if(hmac) {
        memcpy(ret->turn_attr_hmac, hmac, 20);
    } else {
        memset(ret->turn_attr_hmac, 0x00, 20);
    }

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_message_integrity);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_error_create(uint16_t code, const char* reason, size_t len, struct iovec* iov) {
    struct turn_attr_error_code* ret = NULL;
    uint8_t class = code / 100;
    uint8_t number = code % 100;
    size_t real_len = len;

    /* reason can be as long as 763 bytes */
    if(len > 763) {
        return NULL;
    }

    /* class MUST be between 3 and 6 */
    if(class < 3 || class > 6) {
        return NULL;
    }

    /* number MUST be between 0 and 99 */
    if(number > 99) {
        return NULL;
    }

    /* real_len, attribute header size and padding must be a multiple of four */
    if((real_len + 4) % 4) {
        real_len += (4 - (real_len % 4));
    }

    if(!(ret = malloc(sizeof(struct turn_attr_error_code) + real_len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_ERROR_CODE);
    ret->turn_attr_len = htons(4 + real_len);

    if(is_little_endian()) {
        ret->turn_attr_reserved_class = class << 16;
    } else { /* big endian */
        ret->turn_attr_reserved_class = class;
    }

    ret->turn_attr_number = number;

    /* even if strlen(reason) < len, strncpy will add extra-zero
     * also no need to add final NULL character since length is known (TLV)
     */
    strncpy((char*)ret->turn_attr_reason, reason, real_len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_error_code) + real_len;

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_unknown_attributes_create(const uint16_t* unknown_attributes, size_t attr_size, struct iovec* iov) {
    size_t len = 0;
    size_t tmp_len = 0;
    struct turn_attr_unknown_attribute* ret = NULL;
    uint16_t* ptr = NULL;
    size_t i = 0;

    /* length of the attributes MUST be a multiple of 4 bytes
     * so it must be a pair number of attributes
     */
    len = attr_size + (attr_size % 2);

    /* each attribute has 2 bytes length */
    if(!(ret = malloc(sizeof(struct turn_attr_unknown_attribute) + (len * 2) ))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_UNKNOWN_ATTRIBUTES);
    ret->turn_attr_len = htons(attr_size);

    ptr = (uint16_t*)ret->turn_attr_attributes;
    tmp_len = len;

    for(i = 0 ; i < attr_size ; i++) {
        *ptr = htons(unknown_attributes[i]);
        tmp_len--;
        ptr++;
    }

    if(tmp_len) {
        /* take last attribute value */
        i--;
        *ptr = htons(unknown_attributes[i]);
    }

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_unknown_attribute) + (len * 2);
    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_realm_create(const char* realm, size_t len, struct iovec* iov) {
    struct turn_attr_realm* ret = NULL;
    size_t real_len = len;

    /* realm can be as long as 763 bytes */
    if(len > 763) {
        return NULL;
    }

    /* real_len, attribute header size and padding must be a multiple of four */
    if((real_len + 4) % 4) {
        real_len += (4 - (real_len % 4));
    }

    if(!(ret = malloc(sizeof(struct turn_attr_realm) + real_len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_REALM);
    ret->turn_attr_len = htons(len);
    memset(ret->turn_attr_realm, 0x00, real_len);
    memcpy(ret->turn_attr_realm, realm, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_realm) + real_len;

    return (struct turn_attr_hdr*)ret;
}



struct turn_attr_hdr* turn_attr_xor_mapped_address_create(const struct sockaddr* address, uint32_t cookie, const uint8_t* id, struct iovec* iov) {
    return turn_attr_xor_address_create(STUN_ATTR_XOR_MAPPED_ADDRESS, address, cookie, id, iov);
}

struct turn_attr_hdr* turn_attr_software_create(const char* software, size_t len, struct iovec* iov) {
    struct turn_attr_software* ret = NULL;
    size_t real_len = len;

    /* reason can be as long as 763 bytes */
    if(len > 763) {
        return NULL;
    }

    /* real_len, attribute header size and padding must be a multiple of four */
    if((real_len + 4) % 4) {
        real_len += (4 - (real_len % 4));
    }

    if(!(ret = malloc(sizeof(struct turn_attr_software) + real_len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(STUN_ATTR_SOFTWARE);
    ret->turn_attr_len = htons(len);
    memset(ret->turn_attr_software, 0x00, real_len);
    memcpy(ret->turn_attr_software, software, len);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_software) + real_len;

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_alternate_server_create(const struct sockaddr* address, struct iovec* iov) {
    return turn_attr_address_create(STUN_ATTR_ALTERNATE_SERVER, address, iov);
}



/* TURN attributes */

struct turn_attr_hdr* turn_attr_channel_number_create(uint16_t number, struct iovec* iov) {
    struct turn_attr_channel_number* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_channel_number)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_CHANNEL_NUMBER);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_number = htons(number);
    ret->turn_attr_rffu = htons(0);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_channel_number);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_lifetime_create(uint32_t lifetime, struct iovec* iov) {
    struct turn_attr_lifetime* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_lifetime)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_LIFETIME);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_lifetime = htonl(lifetime);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_lifetime);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_xor_peer_address_create(const struct sockaddr* address, uint32_t cookie, const uint8_t* id, struct iovec* iov) {
    return turn_attr_xor_address_create(TURN_ATTR_XOR_PEER_ADDRESS, address, cookie, id, iov);
}

struct turn_attr_hdr* turn_attr_data_create(const void* data, size_t datalen, struct iovec* iov) {
    struct turn_attr_data* ret = NULL;
    size_t real_len = datalen;

    /* datalen, attribute header size and padding must be a multiple of four */
    if((real_len + 4) % 4) {
        real_len += (4 - (real_len % 4));
    }

    if(!(ret = malloc(sizeof(struct turn_attr_data) + real_len))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_DATA);
    ret->turn_attr_len = htons(datalen);
    memset(ret->turn_attr_data, 0x00, real_len);
    memcpy(ret->turn_attr_data, data, datalen);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_data) + real_len;

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_xor_relayed_address_create(const struct sockaddr* address, uint32_t cookie, const uint8_t* id, struct iovec* iov) {
    return turn_attr_xor_address_create(TURN_ATTR_XOR_RELAYED_ADDRESS, address, cookie, id, iov);
}

struct turn_attr_hdr* turn_attr_even_port_create(uint8_t flags, struct iovec* iov) {
    struct turn_attr_even_port* ret = NULL;

    /* attributes must be a multiple of four */
    if(!(ret = malloc(sizeof(struct turn_attr_even_port) + 3))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_EVEN_PORT);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_flags = flags;

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_even_port) + 3;

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_requested_transport_create(uint8_t protocol, struct iovec* iov) {
    struct turn_attr_requested_transport* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_requested_transport)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_REQUESTED_TRANSPORT);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_protocol = protocol;
    ret->turn_attr_reserved = 0;

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_requested_transport);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_dont_fragment_create(struct iovec* iov) {
    struct turn_attr_dont_fragment* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_dont_fragment)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_DONT_FRAGMENT);
    ret->turn_attr_len = htons(0);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_dont_fragment);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_reservation_token_create(const uint8_t* token, struct iovec* iov) {
    struct turn_attr_reservation_token* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_reservation_token)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_RESERVATION_TOKEN);
    ret->turn_attr_len = htons(8);
    memcpy(ret->turn_attr_token, token, 8);

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_reservation_token);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_requested_address_family_create(uint8_t family, struct iovec* iov) {
    struct turn_attr_requested_address_family* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_requested_address_family)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_REQUESTED_ADDRESS_FAMILY);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_family = family;
    ret->turn_attr_reserved = 0;

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_requested_address_family);

    return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_connection_id_create(uint32_t id, struct iovec* iov) {
    struct turn_attr_connection_id* ret = NULL;

    if(!(ret = malloc(sizeof(struct turn_attr_connection_id)))) {
        return NULL;
    }

    ret->turn_attr_type = htons(TURN_ATTR_CONNECTION_ID);
    ret->turn_attr_len = htons(4);
    ret->turn_attr_id = id;

    iov->iov_base = ret;
    iov->iov_len = sizeof(struct turn_attr_connection_id);

    return (struct turn_attr_hdr*)ret;
}


int turn_tcp_send(int sock, const struct iovec* iov, size_t iovlen) {
    ssize_t len = -1;

#if !defined(_WIN32) && !defined(_WIN64)
    struct msghdr msg;

    memset(&msg, 0x00, sizeof(struct msghdr));
    msg.msg_iov = (struct iovec*)iov;
    msg.msg_iovlen = iovlen;
    len = sendmsg(sock, &msg, 0);
#else
    len = sock_writev(sock, iov, iovlen, NULL, 0);
#endif
    return len;
}


int turn_send_message(int transport_protocol, int sock, const struct sockaddr* addr, socklen_t addr_size, size_t total_len, const struct iovec* iov, size_t iovlen) {

    return turn_tcp_send(sock, iov, iovlen);
}

int turn_generate_transaction_id(uint8_t* id) {
    /* 96 bit transaction ID */
    int32_t* id1 = (int32_t*)id;
    int32_t* id2 = (int32_t*)(id + 4);
    int32_t* id3 = (int32_t*)(id + 8);
    *id1 = pj_rand();
    *id2 = pj_rand();
    *id3 = pj_rand();

    return 0;
}




int turn_calculate_integrity_hmac_iov(const struct iovec* iov, size_t iovlen, const unsigned char* key, size_t key_len, unsigned char* integrity) {
#if 1
    pj_hmac_sha1_context ctx;
    unsigned int md_len = 20;
    size_t i = 0;
    pj_hmac_sha1_init(&ctx, (pj_uint8_t*)key,
                      md_len);
    for(i = 0 ; i < iovlen ; i++) {
        pj_hmac_sha1_update(&ctx, iov[i].iov_base, iov[i].iov_len);
    }
    pj_hmac_sha1_final(&ctx,integrity);

    return 0;

#else
    HMAC_CTX ctx;
    unsigned int md_len = SHA_DIGEST_LENGTH;
    size_t i = 0;

    /* MESSAGE-INTEGRITY uses HMAC-SHA1 */


    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, key, key_len, EVP_sha1());

    for(i = 0 ; i < iovlen ; i++) {
        HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
    }
    HMAC_Final(&ctx, integrity, &md_len); /* HMAC-SHA1 is 20 bytes length */
    HMAC_CTX_cleanup(&ctx);
    return 0;
#endif
}


int turn_add_message_integrity(struct iovec* iov, size_t* index, const unsigned char* key, size_t key_len, int add_fingerprint) {
    struct turn_attr_hdr* attr = NULL;
    struct turn_msg_hdr* hdr = iov[0].iov_base;

    if(*index == 0) {
        /* could not place message-integrity or fingerprint in first place */
        return -1;
    }

    if(!(attr = turn_attr_message_integrity_create(NULL, &iov[*index]))) {
        return -1;
    }
    hdr->turn_msg_len += iov[(*index)].iov_len;
    (*index)++;

    /* compute HMAC */
    /* convert length to big endian */
    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    /* do not take into account the attribute itself */
    turn_calculate_integrity_hmac_iov(iov, (*index) - 1, key, key_len,
                                      ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);

    hdr->turn_msg_len = ntohs(hdr->turn_msg_len);

    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    return 0;
}


int turn_xor_address_cookie(int family, uint8_t* peer_addr, uint16_t* peer_port, const uint8_t* cookie, const uint8_t* msg_id) {
    size_t i = 0;
    size_t len = 0;

    switch(family) {
    case STUN_ATTR_FAMILY_IPV4:
        len = 4;
        break;
    case STUN_ATTR_FAMILY_IPV6:
        len = 16;
        break;
    default:
        return -1;
    }

    /* XOR port */
    *peer_port ^= ((cookie[0] << 8) | (cookie[1]));

    /* IPv4/IPv6 XOR cookie (just the first four bytes of IPv6 address) */
    for(i = 0 ; i < 4 ; i++) {
        peer_addr[i] ^= cookie[i];
    }

    /* end of IPv6 address XOR transaction ID */
    for(i = 4 ; i < len ; i++) {
        peer_addr[i] ^= msg_id[i - 4];
    }

    return 0;
}

int turn_parse_message(const char* msg, ssize_t msg_len, struct turn_message* message, uint16_t* unknown, size_t* unknown_size) {
    struct turn_msg_hdr* hdr = NULL;
    /* attributes length */
    ssize_t len = 0;
    const char* ptr = msg;
    size_t unknown_index = 0;
    /* count of XOR-PEER-ADDRESS attribute */
    size_t xor_peer_address_nb = 0;

    /* zeroed structure */
    memset(message, 0x00, sizeof(struct turn_message));

    /* STUN/TURN header MUST be 20 bytes length */
    if(msg_len < 20) {
        /* not a STUN/TURN message */
        return -1;
    }

    hdr = (struct turn_msg_hdr*)ptr;
    message->msg = hdr; /* keep pointer */
    len = ntohs(hdr->turn_msg_len);

    /* check if the length coherent with packet length received */
    if((len + 20) > msg_len) {
        /* too short */
        return -1;
    }

    ptr += 20; /* advance to first attribute */

    if(len % 4) {
        /* length is a multipe of four */
        return -1;
    }

    while(len >= 4) {
        struct turn_attr_hdr* attr = (struct turn_attr_hdr*)ptr;

        /* FINGERPRINT MUST be the last attributes if present */
        if(message->fingerprint) {
            /* when present, the FINGERPRINT attribute MUST be the last attribute */
            /* ignore other message
             */
            return 0;
        }

        /* MESSAGE-INTEGRITY is the last attribute except if FINGERPRINT follow
         * it
         */
        if(message->message_integrity && ntohs(attr->turn_attr_type) !=
                STUN_ATTR_FINGERPRINT) {
            /* with the exception of the FINGERPRINT attribute [...]
             * agents MUST ignore all other attributes that follow MESSAGE-INTEGRITY
             */
            return 0;
        }

        switch(ntohs(attr->turn_attr_type)) {
        case STUN_ATTR_MAPPED_ADDRESS:
            message->mapped_addr = (struct turn_attr_mapped_address*)ptr;
            break;
        case STUN_ATTR_XOR_MAPPED_ADDRESS:
            message->xor_mapped_addr = (struct turn_attr_xor_mapped_address*)ptr;
            break;
        case STUN_ATTR_ALTERNATE_SERVER:
            message->alternate_server = (struct turn_attr_alternate_server*)ptr;
            break;
        case STUN_ATTR_NONCE:
            message->nonce =  (struct turn_attr_nonce*)ptr;
            break;
        case STUN_ATTR_REALM:
            message->realm =  (struct turn_attr_realm*)ptr;
            break;
        case STUN_ATTR_USERNAME:
            message->username =  (struct turn_attr_username*)ptr;
            break;
        case STUN_ATTR_ERROR_CODE:
            message->error_code =  (struct turn_attr_error_code*)ptr;
            break;
        case STUN_ATTR_UNKNOWN_ATTRIBUTES:
            message->unknown_attribute =  (struct turn_attr_unknown_attribute*)ptr;
            break;
        case STUN_ATTR_MESSAGE_INTEGRITY:
            message->message_integrity = (struct turn_attr_message_integrity*)ptr;
            break;
        case STUN_ATTR_FINGERPRINT:
            message->fingerprint = (struct turn_attr_fingerprint*)ptr;
            break;
        case STUN_ATTR_SOFTWARE:
            message->software = (struct turn_attr_software*)ptr;
            break;
        case TURN_ATTR_CHANNEL_NUMBER:
            message->channel_number = (struct turn_attr_channel_number*)ptr;
            break;
        case TURN_ATTR_LIFETIME:
            message->lifetime = (struct turn_attr_lifetime*)ptr;
            break;
        case TURN_ATTR_XOR_PEER_ADDRESS:
            if(xor_peer_address_nb < XOR_PEER_ADDRESS_MAX) {
                message->peer_addr[xor_peer_address_nb] =
                    (struct turn_attr_xor_peer_address*)ptr;
                xor_peer_address_nb++;
            } else {
                /* too many XOR-PEER-ADDRESS attribute,
                 * this will inform process_createpermission() to reject the
                 * request with a 508 error
                 */
                message->xor_peer_addr_overflow = 1;
            }
            break;
        case TURN_ATTR_DATA:
            message->data =  (struct turn_attr_data*)ptr;
            break;
        case TURN_ATTR_XOR_RELAYED_ADDRESS:
            message->relayed_addr = (struct turn_attr_xor_relayed_address*)ptr;
            break;
        case TURN_ATTR_EVEN_PORT:
            message->even_port = (struct turn_attr_even_port*)ptr;
            break;
        case TURN_ATTR_REQUESTED_TRANSPORT:
            message->requested_transport =
                (struct turn_attr_requested_transport*)ptr;
            break;
        case TURN_ATTR_DONT_FRAGMENT:
            message->dont_fragment = (struct turn_attr_dont_fragment*)ptr;
            break;
        case TURN_ATTR_RESERVATION_TOKEN:
            message->reservation_token = (struct turn_attr_reservation_token*)ptr;
            break;
        case TURN_ATTR_REQUESTED_ADDRESS_FAMILY:
            message->requested_addr_family =
                (struct turn_attr_requested_address_family*)ptr;
            break;
        case TURN_ATTR_CONNECTION_ID:
            message->connection_id = (struct turn_attr_connection_id*)ptr;
            break;
        default:
            if(ntohs(attr->turn_attr_type) <= 0x7fff) {
                /* comprehension-required attribute but server does not understand
                 * it
                 */
                if(!(*unknown_size)) {
                    break;
                }
                unknown[unknown_index] = htons(attr->turn_attr_type);
                (*unknown_size)--;
                unknown_index++;
            }
            break;
        }

        /* advance the TLV header (4 bytes) and contents (attr_len) + padding */
        len -= (4 + ntohs(attr->turn_attr_len));
        ptr += (4 + ntohs(attr->turn_attr_len));

        {
            size_t m = (4 + ntohs(attr->turn_attr_len)) % 4;

            if(m) {
                len -= (4 - m);
                ptr += (4 - m);
            }
        }
    }

    *unknown_size = unknown_index;

    return 0;
}

#ifdef __cplusplus
}
#endif