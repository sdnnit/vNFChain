/*
 * test.cpp : Test controller of vNFCModule
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
#include <iomanip>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <vnfchain/if_vnfc.h>

using namespace std;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1       // Use csum_start, csum_offset
#define VIRTIO_NET_HDR_F_DATA_VALID     2       // Csum is valid

#define VIRTIO_NET_HDR_GSO_NONE         0       // Not a GSO frame
#define VIRTIO_NET_HDR_GSO_TCPV4        1       // GSO frame, IPv4 TCP (TSO)
#define VIRTIO_NET_HDR_GSO_UDP          3       // GSO frame, IPv4 UDP (UFO)
#define VIRTIO_NET_HDR_GSO_TCPV6        4       // GSO frame, IPv6 TCP
#define VIRTIO_NET_HDR_GSO_ECN          0x80    // TCP has ECN set

struct virtio_net_hdr
{
    unsigned char  flags;
    unsigned char  gso_type;
    unsigned short hdr_len;
    unsigned short gso_size;
    unsigned short csum_start;
    unsigned short csum_offset;
};

#define ARPHRD_ETHER    1                       // Ethernet
#define ARPOP_REQUEST   1                       // ARP request

struct arphdr {
    unsigned short ar_hrd;                      // Format of hardware address
    unsigned short ar_pro;                      // Format of protocol address
    unsigned char  ar_hln;                      // Length of hardware address
    unsigned char  ar_pln;                      // length of protocol address
    unsigned short ar_op;                       // ARP opcode (command)

    unsigned char  ar_sha[ETH_ALEN];            // Sender hardware address
    unsigned char  ar_sip[4];                   // Sender IP address
    unsigned char  ar_tha[ETH_ALEN];            // Target hardware address
    unsigned char  ar_tip[4];                   // target IP address
};


bool has_whitespace(int c) { return  isspace(c); }
bool has_character(int c)  { return !isspace(c); }

static const string NET_DEVICE  = "eth0";

static const string CMD_CREATE  = "create";
static const string CMD_DELETE  = "delete";
static const string CMD_SERVICE = "service";
static const string CMD_SEND    = "send";
static const string CMD_RECV    = "recv";
static const string CMD_SHOW    = "show";
static const string CMD_HELP    = "help";
static const string CMD_EXIT    = "exit";


static map<string, int>             dev_fd_table;  // A file descriptor table for devices
static map<string, pair<int, int> > svc_fd_table;  // A file descriptor table for services
static list< pair<string, string> > svc_list;      // A service list


static int get_device_fd_by_name(const string& name)
{
    if (dev_fd_table.find(name) == dev_fd_table.end()) {
        throw invalid_argument("Not found the device: " + name);
    }

    return dev_fd_table[name];
}


static pair<int, int>& get_service_fd_by_name(const string& name)
{
    if (svc_fd_table.find(name) == svc_fd_table.end()) {
        throw invalid_argument("Not found the service: " + name);
    }

    return svc_fd_table[name];
}


static void trim(string& str)
{
    string::iterator pos;
    pos = find_if(str.begin(), str.end(), has_character);
    if (pos != str.begin()) {
        str.erase(str.begin(), pos);
    }
}


static void split_token(string& token, string &rem)
{
    string::iterator pos;

    pos = find_if(token.begin(), token.end(), has_whitespace);

    if (pos != token.end()) {
        size_t idx = distance(token.begin(), pos);
        rem = token.substr(idx + 1);
        trim(rem);
        token.erase(pos, token.end());
    }
}


static void exec_help(void)
{
    cout << "Supported commands:" << endl;
    cout << "  create (vnfc|tap) <device>                   -- Create a new device" << endl;
    cout << "  delete <device>                              -- Delete the device" << endl;
    cout << "  service (add|delete) <service> <device>      -- Add/Delete a service" << endl;
    cout << "  send (arp|icmp) <dest IP> <device>           -- Send a packet" << endl;
    cout << "  recv <device> [n packets]                    -- Receive a packet" << endl;
    cout << "  show <device>                                -- Show device features" << endl;
    cout << "  help                                         -- Show command helps" << endl;
    cout << "  exit                                         -- Exit the program" << endl;
}


static void create_device(const string& name, bool is_vnfc)
{
    int fd;

    if (is_vnfc) {
        fd = open("/dev/net/vnfc", O_RDWR);
    } else {
        fd = open("/dev/net/tun", O_RDWR);
    }
    if (fd < 0) {
        throw runtime_error(string("Can't open the device: ") + strerror(errno));
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = VNFC_DEV | VNFC_VNET_HDR;

    if (name.length() >= sizeof(ifr.ifr_name)) {
        throw invalid_argument("Too long device name");
    }

    strncpy(ifr.ifr_name, name.c_str(), name.length() + 1);

    int err = ioctl(fd, VNFC_SET_IFF, (void*)&ifr);
    if (err) {
        close(fd);
        throw runtime_error(string("Can't attach to the device: ") + strerror(errno));
    }

    dev_fd_table[name] = fd;
}


static void exec_create_command(const string& args)
{
    string type(args);
    string name;

    split_token(type, name);
    if (type.empty()) {
        throw invalid_argument("No device name");
    } else if (type == "vnfc") {
        create_device(name, true);
    } else if (type == "tap") {
        create_device(name, false);
    } else {
        throw invalid_argument("Unknown device type: " + type);
    }
}


static void exec_delete_command(const string& name)
{
    int fd = get_device_fd_by_name(name);

    close(fd);

    dev_fd_table.erase(name);
}


static void attach_service(int fd, struct vnfc_req& req, int flags)
{
    req.flags = flags;

    if (ioctl(fd, VNFC_SET_SERVICE, (void*)&req)) {
        svc_fd_table.erase(req.svc_name);
        svc_list.remove(pair<string, string>(req.svc_name, req.dev_name));
        throw runtime_error(string("Can't add a service to the device: ") + strerror(errno));
    }
}


static void add_service(const string& svc_name, const string& dev_name, int flags)
{
    int fd_in = open("/dev/net/vnfc", O_RDONLY);
    if (fd_in < 0) {
        throw runtime_error(string("Can't open the vnfc device: ") + strerror(errno));
    }
    int fd_out = open("/dev/net/vnfc", O_WRONLY);
    if (fd_out < 0) {
        close(fd_in);
        throw runtime_error(string("Can't open the vnfc device: ") + strerror(errno));
    }

    try {
        struct vnfc_req req;
        memset(&req, 0, sizeof(req));

        if (svc_name.length() >= sizeof(req.svc_name)) {
            throw invalid_argument("Too long service name");
        } else if (dev_name.length() >= sizeof(req.dev_name)) {
            throw invalid_argument("Too long device name");
        }

        memcpy(req.svc_name, svc_name.c_str(), svc_name.length() + 1);
        memcpy(req.dev_name, dev_name.c_str(), dev_name.length() + 1);
        req.pid = getpid();

        svc_fd_table[svc_name] = pair<int, int>(fd_in, fd_out);
        svc_list.push_back(pair<string, string>(svc_name, dev_name));

        attach_service(fd_in, req, flags | SERVICE_INPUT_FILE);
        attach_service(fd_out, req, flags | SERVICE_OUTPUT_FILE);
    } catch (const exception& e) {
        close(fd_in);
        close(fd_out);
        throw e;
    }
}


static void detach_service(int fd, struct vnfc_req& req)
{
    if (ioctl(fd, VNFC_SET_SERVICE, (void*)&req)) {
        throw runtime_error(string("Can't delete the service from the device: ") + strerror(errno));
    }
}


static void delete_service(const string& svc_name, const string& dev_name)
{
    pair<int, int> fd_pair = get_service_fd_by_name(svc_name);

    struct vnfc_req req;
    memset(&req, 0, sizeof(req));

    memcpy(req.svc_name, svc_name.c_str(), svc_name.length() + 1);
    memcpy(req.dev_name, dev_name.c_str(), dev_name.length() + 1);
    req.flags = SERVICE_DETACH;

    detach_service(fd_pair.first, req);
    close(fd_pair.first);

    detach_service(fd_pair.second, req);
    close(fd_pair.second);

    svc_fd_table.erase(svc_name);
    svc_list.remove(pair<string, string>(svc_name, dev_name));
}


static void exec_service_command(const string& args)
{
    string type(args);
    string svc_name;

    split_token(type, svc_name);
    if (type.empty()) {
        throw invalid_argument("No service instruction type");
    }

    string dev_name;
    split_token(svc_name, dev_name);
    if (svc_name.empty()) {
        throw invalid_argument("No service name");
    } else if (dev_name.empty()) {
        throw invalid_argument("No device name");
    }

    if (type == "add") {
        add_service(svc_name, dev_name, (SERVICE_UPSTREAM | SERVICE_DOWNSTREAM));
    } else if (type == "delete") {
        delete_service(svc_name, dev_name);
    } else {
        throw invalid_argument("Unknown service instruction: " + type);
    }
}


static void get_host_addresses(vector<unsigned char>& mac, vector<unsigned char>& ip)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw runtime_error(string("Can't open a socket: ") + strerror(errno));
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, NET_DEVICE.c_str(), NET_DEVICE.length() + 1);

    int err = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (err < 0) {
        close(fd);
        throw runtime_error(string("Can't get MAC address: ") + strerror(errno));
    }

    mac.clear();
    mac.assign(ETH_ALEN, 0);
    memcpy(&mac[0], ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, NET_DEVICE.c_str(), NET_DEVICE.length() + 1);

    err = ioctl(fd, SIOCGIFADDR, &ifr);
    if (err < 0) {
        close(fd);
        throw runtime_error(string("Can't get IP address: ") + strerror(errno));
    }

    ip.clear();
    ip.assign(4, 0);
    memcpy(&ip[0], &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, 4);
}


static void send_packet(int fd, vector<unsigned char>& packet, size_t hdr_len)
{
    struct virtio_net_hdr gso;
    gso.flags       = VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_UPSTREAM;
    gso.gso_type    = VIRTIO_NET_HDR_GSO_NONE;
    gso.hdr_len     = static_cast<unsigned short>(hdr_len);
    gso.gso_size    = packet.size() - hdr_len;
    gso.csum_start  = 0;
    gso.csum_offset = 0;

    struct iovec iov[2];
    iov[0].iov_base = reinterpret_cast<unsigned char*>(&gso);
    iov[0].iov_len  = sizeof(gso);
    iov[1].iov_base = reinterpret_cast<unsigned char*>(&packet[0]);
    iov[1].iov_len  = packet.size();

    ssize_t n = writev(fd, iov, 2);
    if (n == 0) {
        throw runtime_error("The socket has already been closed");
    } else if (n < 0) {
        throw runtime_error(string("Can't send the packet: ") + strerror(errno));
    }

    cout << "Sent: " << n << " bytes" << endl;
    cout << " -> " << hex;
    for (int i = 0; i < 16; i++) {
        cout << setw(2) << setfill('0') << (int)packet[i] << ' ';
    }
    cout << dec << endl;
}


static void set_ether_header(struct ethhdr& ether, const vector<unsigned char>& dest, unsigned short ethtype)
{
    memcpy(ether.h_dest, &dest[0], ETH_ALEN);

    vector<unsigned char> my_mac_addr;
    vector<unsigned char> dummy;

    get_host_addresses(my_mac_addr, dummy);
    memcpy(ether.h_source, &my_mac_addr[0], ETH_ALEN);

    ether.h_proto = htons(ethtype);
}


static void set_arp_header(struct arphdr& arp, const vector<unsigned char>& dest_ip)
{
    arp.ar_hrd = htons(ARPHRD_ETHER);
    arp.ar_pro = htons(ETH_P_IP);
    arp.ar_hln = ETH_ALEN;
    arp.ar_pln = 4;
    arp.ar_op  = htons(ARPOP_REQUEST);

    vector<unsigned char> my_mac_addr;
    vector<unsigned char> my_ip_addr;
    get_host_addresses(my_mac_addr, my_ip_addr);

    memcpy(arp.ar_sha, &my_mac_addr[0], ETH_ALEN);
    memcpy(arp.ar_sip, &my_ip_addr[0], 4);
    memset(arp.ar_tha, 0xFF, ETH_ALEN);
    memcpy(arp.ar_tip, &dest_ip[0], 4);
}


static void send_arp_packet(int fd, const string& dest)
{
    vector<unsigned char> packet;

    packet.assign(sizeof(struct ethhdr) + sizeof(struct arphdr), 0);

    struct ethhdr *ether;
    ether = reinterpret_cast<struct ethhdr*>(&packet[0]);

    const vector<unsigned char> bc_mac_addr(ETH_ALEN, 0xFF);
    set_ether_header(*ether, bc_mac_addr, ETH_P_ARP);


    struct arphdr *arp;
    arp = reinterpret_cast<struct arphdr*>(&packet[sizeof(struct ethhdr)]);

    vector<unsigned char> dest_ip_addr(4, 0x0);
    if (inet_pton(AF_INET, dest.c_str(), &dest_ip_addr[0]) != 1) {
        throw invalid_argument("Invalid IPv4 address: " + dest);
    }
    set_arp_header(*arp, dest_ip_addr);

    send_packet(fd, packet, sizeof(struct ethhdr) + sizeof(struct arphdr));
}


static void exec_send_command(const string& args)
{
    string type(args);
    string addr;
    string name;

    split_token(type, addr);
    if (addr.empty()) {
        throw invalid_argument("No destination address");
    }
    split_token(addr, name);
    if (name.empty()) {
        throw invalid_argument("No interface name");
    }

    int fd;
    fd = get_device_fd_by_name(name);

    if (type == "arp") {
        send_arp_packet(fd, addr);
    } else if (type == "icmp") {
        throw runtime_error("Unsupported packet type: " + type);
    } else {
        throw invalid_argument("Unknown packet type: " + type);
    }
}


static void recv_packet(int fd, vector<unsigned char>& packet)
{
    struct virtio_net_hdr gso;
    memset(&gso, 0, sizeof(gso));

    struct iovec iov[2];
    iov[0].iov_base = reinterpret_cast<unsigned char*>(&gso);
    iov[0].iov_len  = sizeof(gso);
    iov[1].iov_base = reinterpret_cast<unsigned char*>(&packet[0]);
    iov[1].iov_len  = packet.size();

    ssize_t n = readv(fd, iov, 2);
    if (n == 0) {
        throw runtime_error("The socket has already been closed");
    } else if (n < 0) {
        throw runtime_error(string("Can't receive a packet: ") + strerror(errno));
    }

    cout << "Received: " << n << " bytes";
    if (gso.flags & VIRTIO_NET_HDR_F_DOWNSTREAM) {
        cout << " [down]" << endl;
    } else {
        cout << endl;
    }
    cout << " -> " << hex;
    for (int i = 0; i < min(static_cast<int>(n), 16); i++) {
        cout << setw(2) << setfill('0') << (int)packet[i] << ' ';
    }
    cout << dec << endl;
}


static void exec_recv_command(const string& args)
{
    string name(args);
    string temp;

    split_token(name, temp);
    if (name.empty()) {
        throw invalid_argument("No interface name");
    }

    size_t nr_packets;
    if (temp.empty()) {
        nr_packets = 1;
    } else {
        nr_packets = atoi(temp.c_str());
        if ((nr_packets == 0) || (nr_packets > 100)) {
            throw invalid_argument("Invalid option n: " + temp);
        }
    }

    int fd;
    fd = get_device_fd_by_name(name);

    vector<unsigned char> packet(2048, 0);

    for (int i = 0; i < nr_packets; i++) {
        recv_packet(fd, packet);
    }
}


static void exec_show_command(const string& name)
{
    int fd;

    fd = get_device_fd_by_name(name);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    int err = ioctl(fd, TUNGETIFF, (void*)&ifr);
    if (err) {
        throw runtime_error(string("Can't get device features: ") + strerror(errno));
    }
    cout << "Features        : 0x" << hex << ifr.ifr_flags << endl;
    cout << dec;

    int vnet_hdr_sz;
    err = ioctl(fd, VNFC_GET_VNET_HDR_SZ, (void*)&vnet_hdr_sz);
    if (err) {
        throw runtime_error(string("Can't get vnet header size: ") + strerror(errno));
    }
    cout << "Vnet header size: " << vnet_hdr_sz << " bytes" << endl;

    int sndbuf;
    err = ioctl(fd, VNFC_GET_SNDBUF, (void*)&sndbuf);
    if (err) {
        throw runtime_error(string("Can't get buffer size: ") + strerror(errno));
    }
    cout << "Buffer size     : " << sndbuf << " bytes" << endl;
}


static bool exec_command(const string& cmd, const string& args)
{
    try {
        if (cmd == CMD_EXIT) {
            return false;
        } else if (cmd == CMD_HELP) {
            exec_help();
        } else if (cmd == CMD_CREATE) {
            exec_create_command(args);
        } else if (cmd == CMD_DELETE) {
            exec_delete_command(args);
        } else if (cmd == CMD_SERVICE) {
            exec_service_command(args);
        } else if (cmd == CMD_SEND) {
            exec_send_command(args);
        } else if (cmd == CMD_RECV) {
            exec_recv_command(args);
        } else if (cmd == CMD_SHOW) {
            exec_show_command(args);
        } else {
            throw invalid_argument("Unknown command: " + cmd);
        }
    } catch (const exception& e) {
        cerr << "ERROR: " << e.what() << endl;
    }
    return true;
}


static void user_input(string& cmd, string& args)
{
    cmd.clear();
    args.clear();

    do {
        cout << "> ";
        getline(cin, cmd);
        trim(cmd);
        if (cin.eof()) {
            cout << endl;
            cmd = CMD_EXIT;
        }
    } while (cmd.empty());

    split_token(cmd, args);
}


static void sig_handler(int sig, siginfo_t *info, void *unused)
{
    pid_t pid;
    int flag;

    pid  = info->si_int & 0xFFFF;
    flag = (info->si_int >> 16) & 0xFFFF;

    cout << "SIGNAL(" << getpid() << "): next = " << pid <<
            ", direction = " << ((flag == SERVICE_UPSTREAM) ? "up" : "down")
         << endl;
}


int main()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sig_handler;
    sa.sa_flags     = SA_SIGINFO;

    if (sigaction(SIG_VNFCHAIN, &sa, NULL) < 0) {
        return -1;
    }

    string cmd;
    string args;

    do {
        user_input(cmd, args);
    } while (exec_command(cmd, args));

    return 0;
}
