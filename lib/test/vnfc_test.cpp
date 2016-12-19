#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "if_vnfc.h"
#include "vnfc.h"
#include "vnfc_io.h"
#include "vnfc_packet.h"
#include "vnfc_pktpool.h"

using namespace std;

static string itos(int value) {
    ostringstream s;
    s << value;
    return s.str();
}


static void test_recv_and_drop(struct vnfc* vnfc)
{
    struct vnfc_packet_vec vector;
    size_t nr_received = 0;

    do {
        int nfds = vnfc_wait_for_recv(vnfc, -1);
        if (nfds < 0) {
            throw runtime_error("Can't receive a packet");
        }
        if (nfds > 1) {
            throw runtime_error("Received from unintended source");
        }

        if (! vnfc_recv_packet_burst(0, vnfc, &vector)) {
            throw runtime_error("Can't get the packet");
        }
        if (! vector.upstream) {
            throw runtime_error("Invalid direction");
        }

        nr_received += vector.size;

        vnfc_drop_packet_burst(vnfc, &vector);
    } while (nr_received < MAX_BURST_PACKETS);
}


static void reader_process()
{
    cerr << "Start a reader process: " << getpid() <<  endl;

    struct vnfc* vnfc;

    vnfc = vnfc_attach("reader", "test", VNFC_BIDIRECTION);
    if (! vnfc) {
        cerr << "ERROR: Can't attach to the vnfc device" << endl;
        return ;
    }

    try {
        assert(vnfc->svr_up);

        test_recv_and_drop(vnfc);
    } catch (const exception& e) {
        cerr << "ERROR: Reader: " << e.what() << endl;
    }

    vnfc_detach(vnfc);

    cerr << "Stop the reader process" << endl;
}


static void test_send(struct vnfc* vnfc, struct vnfc_packet_vec* v)
{
    if (! vnfc_send_packet_burst(vnfc, v)) {
        throw runtime_error("Can't send the packets");
    }
}


static void setup_packet_vector(struct vnfc_pktpool* pool,
                                struct vnfc_packet_vec* v,
                                size_t reqlen, size_t pktlen)
{
    v->size = 0;

    for (uint32_t i = 0; i < MAX_BURST_PACKETS; i++) {
        use_vnfc_packet_default(v, i);

        struct vnfc_packet* packet = v->packets[i];

        if (! pktpool_set_packet(pool, packet, reqlen, v->upstream)) {
            throw runtime_error("Can't allocate a packet: " + itos(i));
        }

        v->size++;

        pktpool_trim_packet(pool, packet, pktlen);
    }
}


static void test_writer_short_up(struct vnfc* vnfc)
{
    cerr << "start test_writer_short_up ... " << endl;

    size_t reqlen = MAX_PACKET_SIZE;
    size_t pktlen = 64;

    struct vnfc_packet_vec vector;
    vector.upstream = true;

    setup_packet_vector(vnfc->pool, &vector, reqlen, pktlen);

    test_send(vnfc, &vector);

    cerr << "done" << endl;
}


static void writer_process()
{
    cerr << "Start a writer process" << endl;

    struct vnfc* vnfc;

    vnfc = vnfc_attach("writer", "test", VNFC_BIDIRECTION);
    if (! vnfc) {
        cerr << "ERROR: Can't attach to the vnfc device" << endl;
        return ;
    }

    this_thread::sleep_for(chrono::milliseconds(500));

    try {
        assert(vnfc->need_to_connect_up && vnfc->pid_to_up > 0);

        test_writer_short_up(vnfc);
    } catch (const exception& e) {
        cerr << "ERROR: Writer: " << e.what() << endl;
    }

    vnfc_detach(vnfc);

    cerr << "Stop the writer process" << endl;
}


static int create_vnfc_device(const string& name)
{
    int fd = open("/dev/net/vnfc", O_RDWR);
    if (fd < 0) {
        perror("open (create_vnfc_device)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = VNFC_DEV | VNFC_VNET_HDR;

    if (name.length() >= sizeof(ifr.ifr_name)) {
        cerr << "Too long device name" << endl;
        close(fd);
        return -1;
    }

    strncpy(ifr.ifr_name, name.c_str(), name.length() + 1);

    int err = ioctl(fd, VNFC_SET_IFF, (void*)&ifr);
    if (err) {
        perror("ioctl (create_vnfc_device)");
        close(fd);
        return -1;
    }

    return fd;
}


int main()
{
    pid_t pid = fork();
    if (pid < 0) {
        cerr << "Can't create a reader process" << endl;
        return -1;
    } else if (pid == 0) {
        this_thread::sleep_for(chrono::milliseconds(100));
        reader_process();
    } else {
        int fd = create_vnfc_device("test");
        if (fd <= 0) {
            cerr << "Can't create a vnfc device" << endl;
        } else {
            writer_process();
        }
        int status;
        waitpid(pid, &status, 0);
        if (fd > 0) {
            close(fd);
        }
    }

    return 0;
}
