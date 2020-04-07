#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<time.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/*
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
	 int numTotalBytes = 0;
	 int numSectionBytes = 0;
	 int sectionIndex = 0;
	 int iterator = 1;
	 int lastIndex = 0;

	 if (strcmp(name, ".") == 0) {
		 wire[12] = 0x00;

		 return 1;
	 }

	 for (int i = 0; i < strlen(name); i++) {
		 if (name[i] == '.') {
			 wire[12 + sectionIndex] = numSectionBytes & 0xFF;
			 sectionIndex = sectionIndex + numSectionBytes + 1;
			 numSectionBytes = 0;
			 iterator = sectionIndex + 1;
			 numTotalBytes++;
			 continue;
		 }

		 wire[12 + iterator] = name[i];

		 numSectionBytes++;
		 numTotalBytes++;

		 if (i == strlen(name) - 1) {
			 lastIndex = 12 + strlen(name) + 1;

			 wire[12 + sectionIndex] = numSectionBytes & 0xFF;
			 numTotalBytes++;
		 }

		 iterator++;
	 }

	 wire[lastIndex] = 0x00;

	 numTotalBytes++;

	 return numTotalBytes;
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
	/*
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
	 char* name = malloc(1026);
	 int index = *indexp;
	 int j = 0, length = 0;
	 int jumpIndex, numBytes;
	 int indexToUse = index;

	 while (1) {
		 numBytes = wire[indexToUse];

		 if (numBytes == 0) {
			 index++;
			 break;
		 }

		 if (indexToUse == index) {
			 index++;
		 }

		 indexToUse++;

		 if (numBytes >= 192) {
			 jumpIndex = wire[indexToUse];
			 indexToUse = jumpIndex;

			 continue;
		 }

		 for (int i = 0; i < numBytes; i++) {
			 char letter = wire[indexToUse];
			 name[j] = letter;
			 j++;
			 indexToUse++;
			 length++;
		 }

		 name[j] = '.';
		 j++;
		 length++;
	 }

	 name[length - 1] = '\0';
	 name = realloc(name, length);

	 return name;
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/*
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
	 dns_rr rr = {};

	 char* name = name_ascii_from_wire(wire, indexp);

	 rr.name = name;

	 int index = *indexp;

	 while (1) {
		 int num = wire[index];

		 if (num == 0) {
			 break;
		 }

		 index++;
	 }

	 int firstByte = wire[index];
	 int secondByte = wire[index + 1];
	 firstByte = firstByte << 8;
	 int type = firstByte | secondByte;
	 rr.type = type;

	 index = index + 2;

	 firstByte = wire[index];
	 secondByte = wire[index + 1];
	 firstByte = firstByte << 8;
	 int class = firstByte | secondByte;
	 rr.class = class;

	 index = index + 2;

	 firstByte = wire[index];
	 secondByte = wire[index + 1];
	 int thirdByte = wire[index + 2];
	 int fourthByte = wire[index + 3];
	 firstByte = firstByte << 24;
	 secondByte = secondByte << 16;
	 thirdByte = thirdByte << 8;
	 int ttl = firstByte | secondByte | thirdByte | fourthByte;
	 rr.ttl = ttl;

	 index = index + 4;

	 firstByte = wire[index];
	 secondByte = wire[index + 1];
	 firstByte = firstByte << 8;
	 int rdata_len = firstByte | secondByte;
	 rr.rdata_len = rdata_len;

	 index = index + 2;

	 unsigned char* rdata = malloc(rdata_len);

	 for (int i = 0; i < rdata_len; i++) {
		 rdata[i] = wire[index];
		 index++;
	 }

	 rr.rdata = rdata;

	 return rr;
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/*
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
	 unsigned char queryID[2];

	 srand(time(0));
	 int randomID = rand();

	 queryID[0] = (randomID << 8) & 0xFF;
	 queryID[1] = randomID & 0xFF;

	 wire[0] = queryID[0];
	 wire[1] = queryID[1];
	 wire[2] = 0x01;
	 wire[3] = 0x00;
	 wire[4] = 0x00;
	 wire[5] = 0x01;
	 wire[6] = 0x00;
	 wire[7] = 0x00;
	 wire[8] = 0x00;
	 wire[9] = 0x00;
	 wire[10] = 0x00;
	 wire[11] = 0x00;

	 int nameLength = name_ascii_to_wire(rr.name, wire);

	 wire[12 + nameLength] = 0x00;
	 wire[12 + nameLength + 1] = 0x01;
	 wire[12 + nameLength + 2] = 0x00;
	 wire[12 + nameLength + 3] = 0x01;

	 nameLength = nameLength + 12 + 4;

	 return nameLength;
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/*
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */
	 dns_rr rr = {};
	 rr.name = qname;
	 rr.type = qtype;
	 rr.class = 1;

	 return rr_to_wire(rr, wire, 1);
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/*
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */

	 dns_answer_entry* result = malloc(sizeof *result);
	 dns_answer_entry* itr = result;

	 char *qname2 = malloc(strlen(qname) + 1);
	 strcpy(qname2, qname);

	 int firstByte = wire[6];
	 int secondByte = wire[7];
	 firstByte = firstByte << 8;
	 int numRRs = firstByte | secondByte;

	 if (numRRs == 0) {
		 return NULL;
	 }

	 int index = 12 + strlen(qname) + 2 + 4;

	 for (int i = 0; i < numRRs; i++) {
		 dns_rr rr = rr_from_wire(wire, &index, 1);

		 while (1) {
			 int num = wire[index];

			 if (num == 0) {
				 break;
			 }

			 index++;
		 }

		 index = index + 2 + 2 + 4 + 2 + rr.rdata_len;

		 if (strcmp(rr.name, qname2) == 0 && rr.type == qtype) {
			 char** ip[4][3];

			 for (int j = 0; j < rr.rdata_len; j++) {
				 sprintf((char * restrict)ip[j], "%d", rr.rdata[j]);
			 }

			 char* val = malloc(1024);

			 for (int j = 0; j < rr.rdata_len; j++) {
				 strcat(val, (const char * restrict)ip[j]);
				 strcat(val, ".");
			 }

			 val[strlen(val) - 1] = '\0';
			 val = realloc(val, strlen(val) + 1);

			 itr->value = val;

			 if (i < numRRs - 1) {
				 itr->next = malloc(sizeof *result);
				 itr = itr->next;
			 }
		 }

		 else if (strcmp(rr.name, qname2) == 0 && rr.type == 5) {
			 int rdataIndex = index - rr.rdata_len;
			 qname2 = name_ascii_from_wire(wire, &rdataIndex);
			 qname2 = realloc(qname2, strlen(qname2) + 1);
			 canonicalize_name(qname2);
			 itr->value = qname2;
			 itr->next = malloc(sizeof *result);
			 itr = itr->next;
		 }
	 }

	 itr->next = NULL;

	 return result;
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, unsigned short port) {
	/*
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
	 struct sockaddr_in ip4addr;
	 memset(&ip4addr, 0, sizeof(ip4addr));

	 ip4addr.sin_family = AF_INET;
	 ip4addr.sin_port = htons(port);
	 ip4addr.sin_addr.s_addr = inet_addr(server);
	 //inet_pton(AF_INET, server, &ip4addr.sin_addr);

	 int sfd = socket(AF_INET, SOCK_DGRAM, 0);

	 if (connect(sfd, (struct sockaddr *)&ip4addr, sizeof(struct sockaddr_in)) < 0) {
		 fprintf(stderr, "Could not connect\n");
		 exit(EXIT_FAILURE);
	 }

	 unsigned char* buffer[1024];
	 send(sfd, request, requestlen, 0);

	 int sizeOfResponse = recv(sfd, buffer, 1024, 0);
	 close(sfd);

	 response = realloc(response, sizeOfResponse);
	 memcpy(response, buffer, sizeOfResponse);

	 return sizeOfResponse;
}

dns_answer_entry *resolve(char *qname, char *server, char *port) {
	int requestLength = strlen(qname) + 2 + 12 + 4;

	unsigned char* wire = malloc(requestLength);

	requestLength = create_dns_query(qname, 1, wire);

	wire = realloc(wire, requestLength);

	unsigned char* response = malloc(1);

	int thePort = atoi(port);

	send_recv_message(wire, requestLength, response, server, thePort);

	get_answer_address(qname, 1, response);
}

int main(int argc, char *argv[]) {
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL) {
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}
