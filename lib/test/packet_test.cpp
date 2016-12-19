#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstdint>

#include "vnfc_pktpool.h"
#include "vnfc_packet.h"
#include "utils/objpool.h"

using namespace std;

static string itos(int value) {
    ostringstream s;
    s << value;
    return s.str();
}

static void test_packet_fields(const vnfc_pktpool* pool,
                               const struct vnfc_packet *packet, size_t len)
{
    if (packet->zero) {
        throw runtime_error("Invalid zero field: " + itos(packet->zero));
    }
    if (! packet->meta) {
        throw runtime_error("Invalid meta");
    }
    if (packet->meta->buf_len != len + sizeof(*packet->meta)) {
        throw runtime_error("Invalid buf_len: " + itos(packet->meta->buf_len)
                            + " (must be " +
                            itos(len + sizeof(*packet->meta))+ ")");
    }
    if (packet->pool != pool) {
        throw runtime_error("Invalid pool");
    }
    if (packet->index >= pool->up->nr_chunks) {
       throw runtime_error("Invalid index: " + itos(packet->index));
    }
    if (packet->data_len != len) {
       throw runtime_error("Invalid len: " + itos(packet->data_len) +
                           " (must be " + itos(len) + ")");
    }
    if (! packet->data) {
        throw runtime_error("Data has not been set");
    }
    if (! packet->upstream) {
        throw runtime_error("Invalid stream direction");
    }
}


static void test_alloc_and_free(struct vnfc_pktpool* pool, size_t reqlen,
                                size_t pktlen, size_t nr_packets)
{
    struct vnfc_packet packet;

    for (uint32_t i = 0; i < nr_packets; i++) {
        if (! pktpool_set_packet(pool, &packet, reqlen, true)) {
            throw runtime_error("Can't allocate a packet: " + itos(i));
        }
        test_packet_fields(pool, &packet, reqlen);


        pktpool_trim_packet(pool, &packet, pktlen);
        test_packet_fields(pool, &packet, pktlen);

        struct vnfc_packet recv_packet;

        if (! pktpool_get_packet(pool, &recv_packet, packet.index, true)) {
            throw runtime_error("Can't get the packet: " + itos(i));
        }
        test_packet_fields(pool, &recv_packet, pktlen);

        pktpool_release_packet(&recv_packet);
    }
}


static void test_short(struct vnfc_pktpool* pool)
{
    cerr << "start test_short ... " << endl;

    size_t reqlen     = MAX_PACKET_SIZE;
    size_t pktlen     = 64;
    size_t nr_packets = 10;

    test_alloc_and_free(pool, reqlen, pktlen, nr_packets);

    cerr << "done" << endl;
}


static void test_large(struct vnfc_pktpool* pool)
{
    cerr << "start test_large ... " << endl;

    size_t reqlen     = MAX_PACKET_SIZE;
    size_t pktlen     = MAX_PACKET_SIZE;
    size_t nr_packets = 10;

    test_alloc_and_free(pool, reqlen, pktlen, nr_packets);

    cerr << "done" << endl;
}


int main()
{
    struct vnfc_pktpool* pool = pktpool_init("test");
    if (! pool) {
        cerr << "ERROR: Can't initialize a packet pool" << endl;
        return -1;
    }

    try {
        test_short(pool);

        test_large(pool);
    } catch (const exception& e) {
        cerr << "ERROR: " << e.what() << endl;
    }

    pktpool_exit(pool, true);

    return 0;
}
