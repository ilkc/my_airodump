#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BEACON_FRAME_TYPE 0x80
#define MAX_BEACON_LENGTH 100
#define ESSID_HDR_POS 61
#define DATA_FRAME_TYPE 2 // packet[24] 에 & 0x0C 하고 >> 2 까지 한게 이거야야됨

typedef struct{
    u_char BSSID[6];
    u_char ESSID[100];
    u_char ENC[10];
    int essid_length;
    int data;
    int Beacons;
    int PWR;
    int radiotap_v;
    
}BEACON_;

// limit 100 
// 마지막은 비워두고 안쓰고 ESSID 을 NULL로 둘 용도로 +1
BEACON_ arr_beacon[MAX_BEACON_LENGTH+1];

void initializeStruct(BEACON_ * arr_beacon){
    for (int i = 0; i < MAX_BEACON_LENGTH + 1; i++) {
        arr_beacon[i].data = 0;
        arr_beacon[i].Beacons = 0;
        arr_beacon[i].essid_length = 0;
        arr_beacon[i].PWR= 0;
        arr_beacon[i].radiotap_v= 0;
        memset(arr_beacon[i].ESSID, 0, sizeof(arr_beacon[i].ESSID));
        memset(arr_beacon[i].BSSID, 0, sizeof(arr_beacon[i].BSSID));
    }
}

void print_beacon_frame(int current_channel){
    system("clear");
    printf("[ ch : %d ] \n", current_channel);
    printf("BSSID               PWR   Beacons   #Data   ESSID\n");
    if(arr_beacon[0].ESSID[0] == '\0') return;

    for(int i=0; i<100; i++){
        if(arr_beacon[i].BSSID[0] == '\0') return;
        printf("%02X:%02X:%02X:%02X:%02X:%02X",
               arr_beacon[i].BSSID[0], arr_beacon[i].BSSID[1], arr_beacon[i].BSSID[2],
               arr_beacon[i].BSSID[3], arr_beacon[i].BSSID[4], arr_beacon[i].BSSID[5]);
        printf("   %3d", arr_beacon[i].PWR-256);
        printf("   %7d", arr_beacon[i].Beacons);
        printf("   %5d", arr_beacon[i].data);
        printf("   %s \n", arr_beacon[i].ESSID);
    }


}

void insert_packet_in_struct(BEACON_ *beacon, const u_char *packet){
    //printf("in fun insert_packet\n");
    int rssi_offset = 0;
    int essid_length = packet[ESSID_HDR_POS];
    memcpy(beacon->BSSID, &packet[34], 6);
    beacon->essid_length = packet[ESSID_HDR_POS];
    memcpy(beacon->ESSID, &packet[ESSID_HDR_POS+1], beacon->essid_length);
    beacon->PWR = packet[18];
}
/* 원래 loop 하려고 했으나 channel hopping 을 하려고 하니 이 방법은 안되어서 메인으로 옮겨서 진행하여 사라진 함수...
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Beacon Frame 타입 확인
    //printf("packet[24] : %x\n", packet[24]);
    int i;
    int check = 1;
    if (packet[24] == BEACON_FRAME_TYPE) {

        for(i = 0; (arr_beacon[i].ESSID[0] != '\0') && i<100; i++){
            int n = memcmp(arr_beacon[i].BSSID, &packet[34], 6);
            if(n == 0){
                arr_beacon[i].data++;
                check = 0;
                break;
            }else{
                continue;
            }
        }
        if(check == 1){
            //printf("in_Check: %d \n", check);
            for(i=0; i<100; i++){
                if(arr_beacon[i].ESSID[0] == '\0'){
                    insert_packet_in_struct(&arr_beacon[i], packet);
                    break;
                }
            }
            
        }
    
    //print_beacon_frame();
    }
}
*/
void change_channel(const char *interface, int *current_channel) {
    char command[100];
    sprintf(command, "iwconfig %s channel %d", interface, *current_channel);
    system(command);

    // 채널 순환
    *current_channel = (*current_channel % 14) + 1;
}

int main() {
    char *dev = "mon0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    int current_channel = 1;
    initializeStruct(arr_beacon);
    int data_type;

    // 인터페이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 루프
    //pcap_loop(handle, -1, process_packet, NULL);

    while (1) {
        // 패킷 캡처
        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            // 패킷 처리
            int i;
            int check = 1;
            if (packet[24] == BEACON_FRAME_TYPE) {
                for(i = 0; (arr_beacon[i].ESSID[0] != '\0') && i<100; i++){
                    int n = memcmp(arr_beacon[i].BSSID, &packet[34], 6);
                    if(n == 0){ // 같으면
                        arr_beacon[i].Beacons++;
                        check = 0;
                        break;
                    }else{
                        continue;
                    }
                }
                if(check == 1){
                    //printf("in_Check: %d \n", check);
                    for(i=0; i<100; i++){
                        if(arr_beacon[i].ESSID[0] == '\0'){
                            insert_packet_in_struct(&arr_beacon[i], packet);
                            break;
                        }
                    }
                }
                if(packet[134] == 0x30){ // WPA

                }
            }else if((packet[24] & 0x0C) >> 2 == DATA_FRAME_TYPE){ //Frame Control Field에 앞 1바이트의 5,6 번째 비트 type이고 이게 0x10 이어야지 Data frame
                for(int i=0; i<100; i++){
                    int n = memcmp(arr_beacon[i].BSSID, &packet[28], 6);
                    if(n == 0){ // 같으면
                        arr_beacon[i].data++;
                        break;
                    }
                }
            }


            // 출력
            print_beacon_frame(current_channel);
            // 채널 변경
            change_channel(dev, &current_channel);

        }
    }

    pcap_close(handle);
    return 0;
}