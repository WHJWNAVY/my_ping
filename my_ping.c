#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define MAX_IP_HEADER_SIZE 60
#define MAX_RECV_BUFF_SIZE (MAX_IP_HEADER_SIZE + sizeof(struct icmp))

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif

#define PING_TIMEOUT 1                           // sec
#define REQUEST_TIMEOUT (PING_TIMEOUT * 1000000) // us
#define REQUEST_RETRYCNT 3
// #define USE_REQUEST_RETRY 1

#define _DEBUG_ 1

#ifdef _DEBUG_
#define DEBUG_PRINT(FMT, ...)                                                    \
    do                                                                           \
    {                                                                            \
        fprintf(stderr, "(%s:%d) " FMT "\n", __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define DEBUG_PRINT(FMT, ...)
#endif

static uint16_t cal_checksum(uint16_t *addr, size_t size) {
    int32_t numLeft = size;
    int32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (numLeft > 1) {
        sum += *w++;
        numLeft -= 2;
    }

    if (numLeft == 1) {
        *(uint8_t *)(&answer) = *(uint8_t *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

static uint64_t get_timestamp(void) // us
{
    struct timeval now = {0};
    return ((gettimeofday(&now, NULL) != 0) ? 0 : now.tv_sec * 1000000 + now.tv_usec);
}

static char *addrinfo_ntop(struct addrinfo *addrinfo) {
    void *addrn = NULL;
    static char addrs[INET6_ADDRSTRLEN + 1] = {0};

    memset(addrs, 0, sizeof(addrs));

    switch (addrinfo->ai_family) {
        case AF_INET:
            addrn = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            addrn = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
            break;
    }

    // Extract source IP address from received ethernet frame.
    if (inet_ntop(addrinfo->ai_family, addrn, addrs, sizeof(addrs)) == NULL) {
        DEBUG_PRINT("inet_ntop failed!error message: %s", strerror(errno));
        return NULL;
    }
    return addrs;
}

static bool addrinfo_isloopback(struct addrinfo *addrinfo) {
#ifndef IN4_IS_ADDR_LOOPBACK
#define IN4_IS_ADDR_LOOPBACK(a) (((struct in_addr *)(a))->s_addr == htonl(INADDR_LOOPBACK))
#endif

    void *addrn = NULL;
    switch (addrinfo->ai_family) {
        case AF_INET:
            addrn = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
            return IN4_IS_ADDR_LOOPBACK(addrn);
            break;
        case AF_INET6:
            addrn = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
            return IN6_IS_ADDR_LOOPBACK(addrn);
            break;
    }
    return false;
}

static int32_t ping_icmp_send(int32_t sockfd, struct addrinfo *addrinfo) {
    int32_t ret = 0;
#ifdef REQUEST_RETRYCNT
    int32_t retry_count = 0;
    uint64_t start_time = 0;
    uint64_t delay_time = 0;
#endif
    bool from_loopback = false;
    struct addrinfo peeraddr = {0};
    socklen_t addrlen = 0;
    struct iphdr *piphdr = NULL;
    int32_t ip_header_size = 0;
    struct icmp icmp_request = {0};
    struct icmp *icmp_response = NULL;
    uint16_t id = 0, seq = 0;

    char recv_buf[MAX_RECV_BUFF_SIZE] = {0};

    id = (uint16_t)getpid();
    seq = (uint16_t)1;
    icmp_request.icmp_type = addrinfo->ai_family == AF_INET6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
    icmp_request.icmp_code = 0;
    icmp_request.icmp_cksum = 0;
    icmp_request.icmp_id = htons(id);
    icmp_request.icmp_seq = htons(seq);

    if (addrinfo->ai_family == AF_INET) {
        icmp_request.icmp_cksum = cal_checksum((uint16_t *)&icmp_request, sizeof(icmp_request));
    }

#ifdef REQUEST_RETRYCNT
    start_time = get_timestamp();
#endif

    // send frame to socket
    addrlen = addrinfo->ai_addrlen;
    if ((ret = sendto(sockfd, (const char *)&icmp_request, sizeof(icmp_request), 0, addrinfo->ai_addr, addrlen)) < 0) {
        DEBUG_PRINT("sendto failed! error message: %s", strerror(errno));
        return ((errno == 0) ? -1 : errno);
    }

retry:

#ifdef REQUEST_RETRYCNT
    if ((delay_time > REQUEST_TIMEOUT) || (retry_count > REQUEST_RETRYCNT)) {
        DEBUG_PRINT("request timed out!");
        return -1;
    }
    if (retry_count) {
        DEBUG_PRINT("request retry %d!", retry_count);
    }
    delay_time = get_timestamp() - start_time;
    retry_count++;
#endif

#if 1
    memcpy(&peeraddr, addrinfo, sizeof(peeraddr));
    addrlen = peeraddr.ai_addrlen;
    ret = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, peeraddr.ai_addr, &addrlen);
    from_loopback = addrinfo_isloopback(&peeraddr);
    DEBUG_PRINT("recv from loopback %s", from_loopback ? "true" : "false");
#else
    ret = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
#endif
    if (ret == 0) {
        DEBUG_PRINT("recv failed! error message: %s", strerror(errno));
        return ((errno == 0) ? -1 : errno);
    } else if (ret < 0) {
#ifdef USE_REQUEST_RETRY
        if (errno == EAGAIN) {
            /* No data available yet, try to receive again. */
            goto retry;
        } else
#endif
        {
            DEBUG_PRINT("recvfrom failed! error message: %s", strerror(errno));
            return ((errno == 0) ? -1 : errno);
        }
    }

    switch (addrinfo->ai_family) {
        case AF_INET:
            piphdr = (struct iphdr *)recv_buf;
            ip_header_size = (piphdr->ihl << 2);
            break;
        case AF_INET6:
            ip_header_size = 0;
            break;
    }

    icmp_response = (struct icmp *)(recv_buf + ip_header_size);
    icmp_response->icmp_cksum = ntohs(icmp_response->icmp_cksum);
    icmp_response->icmp_id = ntohs(icmp_response->icmp_id);
    icmp_response->icmp_seq = ntohs(icmp_response->icmp_seq);

    // check for an IP ethernet frame carrying ICMP echo reply
    if (icmp_response->icmp_id != id) {
        DEBUG_PRINT("invalid icmp id %d:%d", id, icmp_response->icmp_id);
        return -1;
    }
    switch (addrinfo->ai_family) {
        case AF_INET:
            if (icmp_response->icmp_type != ICMP_ECHOREPLY) {
#ifdef REQUEST_RETRYCNT
                if (from_loopback) {
                    goto retry;
                }
#endif
                DEBUG_PRINT("invalid icmp type %d:%d", ICMP_ECHOREPLY, icmp_response->icmp_type);
                return -((ICMP_ECHOREPLY == 0) ? 1 : ICMP_ECHOREPLY);
            }
            break;
        case AF_INET6:
            if (icmp_response->icmp_type != ICMP6_ECHO_REPLY) {
#ifdef REQUEST_RETRYCNT
                if (from_loopback) {
                    goto retry;
                }
#endif
                DEBUG_PRINT("invalid icmp6 type %d:%d", ICMP6_ECHO_REPLY, icmp_response->icmp_type);
                return -(ICMP6_ECHO_REPLY);
            }
            break;
    }
    return 0;
}


struct addrinfo_t {
    struct addrinfo *addr;
    struct addrinfo *head;
};

static int32_t ping_sock_init(char *paddrs, bool isv6, int32_t timeouts, int32_t *opsockfd,
                              struct addrinfo_t *opaddrinfo) {
    int32_t ret = 0;
    int32_t sockfd = -1, sockoptint = 0;
    char *target_host = NULL;
    struct timeval timeout = {0};
    struct addrinfo addrinfo_hints = {0};
    struct addrinfo *addrinfo_head = NULL;
    struct addrinfo *addrinfo = NULL;

    target_host = paddrs;

    if (!isv6) {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMP;
        ret = getaddrinfo(target_host, NULL, &addrinfo_hints, &addrinfo_head);
    } else {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET6;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMPV6;
        ret = getaddrinfo(target_host, NULL, &addrinfo_hints, &addrinfo_head);
    }

    if ((ret != 0) || (addrinfo_head == NULL)) {
        DEBUG_PRINT("getaddrinfo failed! error message: %s", gai_strerror(ret));
        goto err;
    }

    opaddrinfo->head = addrinfo_head;

    // addrinfo is a linked list
    for (addrinfo = addrinfo_head; addrinfo != NULL; addrinfo = addrinfo->ai_next) {
        if ((sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) >= 0) {
            // break when we get a socket
            break;
        }
    }

    // never got a valid socket
    if (sockfd < 0) {
        DEBUG_PRINT("socket failed! error message: %s", strerror(errno));
        ret = ((errno == 0) ? -1 : errno);
        goto err;
    }

    DEBUG_PRINT("target host[%s], addrs[%s]", target_host, addrinfo_ntop(addrinfo));

#if 0
    if ((ret = fcntl(sockfd, F_SETFL, O_NONBLOCK)) != 0)
    {
        DEBUG_PRINT("fcntl O_NONBLOCK failed! error message: %s", strerror(errno));
        goto err;
    }
#endif

#if 1
    sockoptint = 1;
    if ((ret = setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &sockoptint, sizeof(sockoptint))) != 0) {
        DEBUG_PRINT("setsockopt %d failed! error message: %s", SO_BROADCAST, strerror(errno));
        ret = ((errno == 0) ? -1 : errno);
        goto err;
    }
#endif

    if (addrinfo->ai_family == AF_INET6) {
        sockoptint = offsetof(struct icmp6_hdr, icmp6_cksum);
        if ((ret = setsockopt(sockfd, SOL_RAW, IPV6_CHECKSUM, &sockoptint, sizeof(sockoptint))) != 0) {
            DEBUG_PRINT("setsockopt %d failed! error message: %s", IPV6_CHECKSUM, strerror(errno));
            ret = ((errno == 0) ? -1 : errno);
            goto err;
        }
    } else {
#if 0
        sockoptint = offsetof(struct icmp, icmp_cksum);
        if ((ret = setsockopt(sockfd, SOL_RAW, IP_CHECKSUM, &sockoptint, sizeof(sockoptint))) != 0)
        {
            DEBUG_PRINT("setsockopt %d failed! error message: %s", IP_CHECKSUM, strerror(errno));
            ret= ((errno == 0) ? -1 : errno);
            goto err;
        }
#endif
    }

    if (timeouts > 0) {
        timeout.tv_sec = timeouts;
        timeout.tv_usec = 0;

        ret = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (ret != 0) {
            DEBUG_PRINT("setsockopt %d failed! error message: %s", SO_SNDTIMEO, strerror(errno));
            ret = ((errno == 0) ? -1 : errno);
            goto err;
        }

        ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (ret != 0) {
            DEBUG_PRINT("setsockopt %d failed! error message: %s", SO_RCVTIMEO, strerror(errno));
            ret = ((errno == 0) ? -1 : errno);
            goto err;
        }
    }

    *opsockfd = sockfd;
    opaddrinfo->addr = addrinfo;

    ret = 0;
err:
    if ((ret != 0) && (sockfd > 0)) {
        close(sockfd);
    }
    return ret;
}

int32_t ping_alive_test(char *paddrs, bool isv6, int32_t timeouts) {
    int32_t ret = 0, sockfd = 0;
    struct addrinfo_t staddrinfo = {0};

    if (paddrs == NULL) {
        ret = -1;
        goto err;
    }

    if ((ret = ping_sock_init(paddrs, isv6, timeouts, &sockfd, &staddrinfo)) != 0) {
        DEBUG_PRINT("ping sock init failed! ret: %d", ret);
        goto err;
    }

    if ((ret = ping_icmp_send(sockfd, staddrinfo.addr)) != 0) {
        DEBUG_PRINT("ping test failed! ret: %d", ret);
        goto err;
    }

    printf("%s is alive!\n", paddrs);
    ret = 0;
err:
    if (staddrinfo.head != NULL) {
        freeaddrinfo(staddrinfo.head);
    }
    if (sockfd > 0) {
        close(sockfd);
    }
    return ret;
}
#if 1
int32_t main(int32_t argc, char **argv)
{
    int32_t i = 0;
    bool isv6 = false;
    char *hostname = NULL;
    if (argc < 2)
    {
        DEBUG_PRINT("Usage: sudo %s [-4 (IPv4) or -6 (IPv6)] hostname/IP address", argv[0]);
        exit(EXIT_FAILURE);
    }

    i = 1;
    if (strcmp(argv[i], "-4") == 0)
    {
        i++;
        isv6 = false;
    } else if (strcmp(argv[i], "-6") == 0)
    {
        i++;
        isv6 = true;
    }

    hostname = argv[i];

    while(true)
    {
        ping_alive_test(hostname, isv6, PING_TIMEOUT);
        sleep(1);
    }
    
    return 0;
}
#endif