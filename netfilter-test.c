#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>


/*

sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
설정하고 시작

*/

void set_iptable(){

	system("sudo iptables -F");
	system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");	
	
}
void free_iptable(){
	system("sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -D INPUT -j NFQUEUE --queue-num 0");
	printf("Delete Rule\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	printf("\n");
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, char *warn)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;	//네트워크 패킷의 헤더 정보 , ph를 사용하여 패킷의 프로토콜, 훅(hook), 패킷 ID 등의 정보를 액세스
	struct nfqnl_msg_packet_hw *hwph;	//네트워크 패킷의 네트워크 인터페이스의 고유한 주소 정보
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
    
	ret = nfq_get_payload(tb, &data);	//nfq_get_payload 이후 패킷의 시작 위치와 패킷의 길이를 알아내고 나서 IP, TCP, HTTP 형식으로 parsing을 한다
	if (ret >= 0) {
		dump(data, ret);
		printf("payload_len=%d\n", ret);

		struct iphdr *ip_header = (struct iphdr *)data;
		if (ip_header->protocol == IPPROTO_TCP) {
			int ip_header_length = ip_header->ihl * 4;
			struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_length);

			int tcp_header_length = tcp_header->doff * 4;
			int total_header_length = ip_header_length + tcp_header_length;
			int payload_length = ret - total_header_length;

			// HTTP 헤더 내에서 "Host" 필드 추출
			unsigned char *http_payload = data + total_header_length;
			int http_payload_length = payload_length;
			char *host_field = "Host: ";

			// "Host: " 문자열을 찾아 호스트 주소 시작 위치를 찾음
			unsigned char *host_start = strstr(http_payload, host_field);
			if (host_start) {
				host_start += strlen(host_field);
				unsigned char *host_end = strchr(host_start, '\n');
				if (host_end) {
					int host_length = host_end - host_start;

					// 호스트 주소를 문자열로 추출
					char host[256]; // 적절한 크기로 변경
					strncpy(host, (char *)host_start, host_length);
					host[host_length] = '\0';
					printf("Host: %s\n",host);
					if (memcmp(host,warn,sizeof(host))==0){
						return -1;
					}else{
						return id;			
					}
				}
			}
		}
		
	}
	fputc('\n', stdout);

	return id;
}




//콜백 함수
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    char *warn = (char *)data; // FBI_Warning을 받아서 사용
    u_int32_t id = print_pkt(nfa, warn);
    if (id == (u_int32_t)-1) {
	printf("Do not Access!\n");
        return nfq_set_verdict(qh, id,NF_ACCEPT , 0, NULL);
	sleep(2);
    }
    printf("return id  : %u\n", id);
    printf("entering callback\n");
    // 유해 사이트라고 판단되는 경우 nfq_set_verdict 함수의 3번째 인자를 NF_ACCEPT에서 NF_DROP으로 변경하여 함수를 호출
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    //네트워크 필터링 큐를 관리하기 위한 핸들
	struct nfq_handle *h;
    //특정 큐를 관리하기 위한 핸들
    //NFQNL_COPY_PACKET  -> 패킷을 복사하여 처리 -> cb로 전달해서 처리
	struct nfq_q_handle *qh;

    //넷링크 네임스페이스를 관리하기 위한 핸들
	struct nfnl_handle *nh;

	char* FBI_Warning = argv[1]; //유해사이트
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));


	set_iptable();
    

	//필터링 큐 Open
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	//libnetfilter_queue에 있는 함수
	//네트워크 필터링을 위해 커널에 바인딩된 프로토콜 패밀리(AF_INET 등)를 해제하는 역할
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	
	/*
	특정 프로토콜 패밀리(AF_INET 등)에 대한 네트워크 필터링을 설정
	h: 핸들
	AF_INET : 바인딩할 프로토콜 패밀리 -> AF_INET은 Ipv4v 필터링활성화
	*/
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	
	/*
	필터링 큐 생성
	h : 핸들
	num : 생성할 큐의 번호,보통 0부터해서 순차 증가
	cb : 콜백함수의 포인터
	NULL(data) : 콜백함수에 전달될 데이터
	*/
	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, FBI_Warning);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	/*
	패킷 처리 큐의 동작 모드를 설정
	qh : 핸들
	NFQNL_COPY_PACKET : 설정할 동작 모드
	0xffff : 동작 모드에 따라 설정할 범위
	*/
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}


	/*
	패킷 처리 큐의 파일 디스크립터(File Descriptor)를 얻는 역할
	h : 핸들
	*/
	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	free_iptable();
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}


