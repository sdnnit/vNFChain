/*
 * simple_service.cpp : Sample uVNF
 *
 * Copyright 2015-17 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <signal.h>

#include <vnfchain/vnfc.h>
#include <vnfchain/vnfc_io.h>
#include <vnfchain/vnfc_packet.h>

using namespace std;

static bool g_is_interrupted;


static void sig_handler(int sig, siginfo_t* info, void* unused)
{
    g_is_interrupted = true;
}


static struct vnfc* init_service(const string& service_name, const string& device_name,
                                int ring_id)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sig_handler;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction");
        return NULL;
    }

    uint32_t flags = VNFC_BIDIRECTION;
    if (ring_id >= 0) {
        flags |= VNFC_DPDK_RING;
    }
    struct vnfc* vnfc = vnfc_attach(service_name.c_str(),
                                   device_name.c_str(),
                                   flags);

    if (! vnfc) {
        return NULL;
    }

    return vnfc;
}


static void exit_service(struct vnfc* vnfc)
{
    vnfc_detach(vnfc);
}


static bool do_process(struct vnfc_packet_vec& v)
{
#if 0
    cout << "Process " << v.size << " packets ("
         << (v.upstream ? "up" : "down") << ")" << endl;

    for (int i = 0; i < v.size; i++) {
        cout << "\t " << i
             << ") len = " << get_vnfc_packet_len(v.packets[i]) << endl;
    }
#endif
    return true;
}


static void start_service(struct vnfc& vnfc)
{
    cout << "[" << vnfc.svc_name << "] Start the service" << endl;

    struct vnfc_packet_vec v;

    while (! g_is_interrupted) {
        int nfds = vnfc_wait_for_recv(&vnfc, 10);
        if (nfds < 0) {
            cerr << "[" << vnfc.svc_name << "] ERROR: Waiting for a packet" << endl;
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (! vnfc_recv_packet_burst(i, &vnfc, &v)) {
                cerr << "[" << vnfc.svc_name << "] ERROR: Can't receive the packet" << endl;
                this_thread::sleep_for(chrono::milliseconds(10));
                continue;
            }

            if (v.size == 0) {
                continue;
            }

            if (! do_process(v)) {
                // Discard the packet
                continue;
            }

            if (! vnfc_send_packet_burst(&vnfc, &v)) {
                cerr << "[" << vnfc.svc_name << "] ERROR: Can't send the packet" << endl;
            }
        }
    }

    cout << "[" << vnfc.svc_name << "] Stop the service" << endl;
}


static void print_help(const string& name)
{
    cerr << "Usage: " << name <<
            " [-n|--name] <service name> [-d|--dev] <device> " \
            "[--use-dpdk-ring] <ring-id>" << endl;
}


int main(int argc, char** argv)
{
    if (argc != 5 && argc != 7) {
        print_help(argv[0]);
        return -1;
    }

    string service_name;
    string device_name;
    int ring_id = -1;

    for (int i = 1; i < argc - 1; i += 2) {
        if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--name")) {
            service_name = argv[i + 1];
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dev")) {
            device_name = argv[i + 1];
        } else if (!strcmp(argv[i], "--use-dpdk-ring")) {
            ring_id = stoi(string(argv[i + 1]));
        }
    }

    if (service_name.empty() || device_name.empty()) {
        print_help(argv[0]);
        return -1;
    }

    struct vnfc* vnfc = init_service(service_name, device_name, ring_id);
    if (! vnfc) {
        cerr << "[" << service_name << "] ERROR: Can't initialize the service" << endl;
        return -1;
    }

    int ret = 0;
    try {
        start_service(*vnfc);
    } catch (const exception& e) {
        cerr << "[" << service_name << "] ERROR: " << e.what() << endl;
        ret = -1;
    }

    exit_service(vnfc);

    return ret;
}
