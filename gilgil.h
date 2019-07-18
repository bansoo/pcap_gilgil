#ifndef GILGIL_H
#define GILGIL_H
#include <stdint.h>
struct gilethernet{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;

};
struct gilIP{


    uint8_t IPlen;
    uint8_t TOS;
    uint16_t totallen;
    uint8_t IFFT[5];
    uint8_t protocol;
    uint8_t checksum[2];
    uint8_t sip[4];
    uint8_t dip[4];
    uint8_t trash[40]; // not used but saved (max length byte = 60)


};
struct gilTCP{
    uint16_t sport;
    uint16_t dport;
    uint8_t trash[8];
    uint8_t TCPlen;
    uint8_t trash2[100]; // not used but saved

};


#endif // GILGIL_H

