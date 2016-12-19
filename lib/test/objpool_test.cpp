#include <iostream>
#include <string>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include "utils/objpool.h"

using namespace std;

const static size_t BUF_SIZE   = 128;
const static size_t NR_BUFS    = 65536;

static string itos(int value) {
    ostringstream s;
    s << value;
    return s.str();
}


static size_t calc_nr_chunks(size_t len)
{
    size_t nr_chunks = len / BUF_SIZE;
    if (len != nr_chunks * BUF_SIZE) {
        nr_chunks++;
    }
    return nr_chunks;
}


static void test_alloc_free_impl(struct objpool* pool,
                                 uint32_t indexes[NR_BUFS],
                                 size_t nr_bufs, size_t nr_packets,
                                 size_t required_size, size_t actual_size)
{
    for (uint32_t i = 0; i < nr_packets; i++) {
        uint32_t index;

        uint8_t* packet = objpool_alloc_chunks(pool, required_size, &index);
        if (! packet) {
            throw runtime_error("Can't get free chunk: " + itos(i));
        } else if (index != get_index_from_chunk(pool, packet)) {
            throw runtime_error("Invalid index:" + itos(index));
        }

        if (calc_nr_chunks(required_size) > calc_nr_chunks(actual_size)) {
            if (! objpool_trim_chunks(pool, index, required_size, actual_size)) {
                throw runtime_error("Can't trim the packet " + itos(index) + ": " +
                                    itos(required_size) + " => " + itos(actual_size));
            }
        }

        indexes[i] = index;
        if (i > 0) {
            if (indexes[i] != indexes[i - 1] + nr_bufs) {
                throw runtime_error("Invalid index: " +
                                    itos(indexes[i]) + " must be " +
                                    itos(indexes[i - 1] + nr_bufs));
            }
        }
    }

    if (objpool_alloc_chunks(pool, required_size, NULL)) {
        throw runtime_error("Over allocation");
    }

    for (uint32_t i = 0; i < nr_packets; i++) {
        uint8_t* packet = get_chunk_from_index(pool, indexes[i]);
        if (! packet) {
            throw runtime_error("Can't get the packet: " + itos(indexes[i]));
        }
        objpool_release_chunks(pool, indexes[i], actual_size);
    }
}


static void test_alloc_free(struct objpool *pool, uint32_t indexes[NR_BUFS],
                            size_t required_size, size_t actual_size)
{
    size_t nr_req_bufs = calc_nr_chunks(required_size);
    size_t nr_req_packets = NR_BUFS / nr_req_bufs;
    if (NR_BUFS != nr_req_packets * nr_req_bufs) {
        nr_req_packets++;
    }
    size_t nr_bufs = calc_nr_chunks(actual_size);
    size_t nr_packets = NR_BUFS / nr_bufs;
    if (NR_BUFS != nr_packets * nr_bufs) {
        nr_packets++;
    }

    size_t nr_diff_bufs = nr_req_bufs - nr_bufs;
    size_t diff = 0;
    if (nr_diff_bufs > 0) {
        diff = nr_diff_bufs / nr_bufs;
        if (nr_diff_bufs != diff * nr_bufs) {
            diff++;
        }
    }

    test_alloc_free_impl(pool, indexes, nr_bufs, nr_packets - diff,
                         required_size, actual_size);
}


static void test_single(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_single ... " << endl;

    size_t required_size = BUF_SIZE * 1;
    size_t actual_size   = BUF_SIZE;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_single_nonalign(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_single_nonalign ... " << endl;

    size_t required_size = BUF_SIZE * 1;
    size_t actual_size   = BUF_SIZE / 2;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_multi(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_multi ... " << endl;

    size_t required_size = BUF_SIZE * 4;
    size_t actual_size   = required_size;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_multi_nonalign1(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_multi_nonalign1 ... " << endl;

    size_t required_size = BUF_SIZE * 4;
    size_t actual_size   = BUF_SIZE * 1;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_multi_nonalign2(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_multi_nonalign2 ... " << endl;

    size_t required_size = BUF_SIZE * 4;
    size_t actual_size   = BUF_SIZE * 2;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_multi_nonalign3(struct objpool* pool, uint32_t indexes[NR_BUFS])
{
    cerr << "start test_multi_nonalign3 ... " << endl;

    size_t required_size = BUF_SIZE * 4;
    size_t actual_size   = BUF_SIZE * 3;

    test_alloc_free(pool, indexes, required_size, actual_size);

    cerr << "done" << endl;
}


static void test_write_and_read_impl(struct objpool* pool,
                                     uint32_t indexes[NR_BUFS],
                                     size_t nr_bufs, size_t nr_packets,
                                     size_t len, size_t burst, size_t nr_times)
{
    for (uint32_t i = 0; i < nr_times; i++) {
	    for (uint32_t j = 0; j < burst; j++) {
            uint32_t index;

            uint8_t* packet = objpool_alloc_chunks(pool, len, &index);
	        if (! packet) {
                throw runtime_error("Can't get free buf: " + itos(j));
            }

            indexes[j] = index;
            if (j > 0) {
                if (indexes[j] != indexes[j - 1] + nr_bufs) {
                    throw runtime_error("Invalid packet index: " +
                                        itos(indexes[j]) + " must be " +
                                        itos(indexes[j - 1] + nr_bufs));
                }
            }
        }

        for (uint32_t j = 0; j < burst; j++) {
            uint8_t* packet = get_chunk_from_index(pool, indexes[j]);
            if (! packet) {
                throw runtime_error("Can't get packet: " + itos(indexes[j]));
            }
            objpool_release_chunks(pool, indexes[j], len);
        }
    }
}


static void test_write_and_read(struct objpool* pool, uint32_t indexes[NR_BUFS],
                                size_t len, size_t burst, size_t nr_times)
{
    size_t nr_bufs = calc_nr_chunks(len);
    size_t nr_packets = NR_BUFS / nr_bufs;
    if (NR_BUFS != nr_packets * nr_bufs) {
	    nr_packets++;
    }

    test_write_and_read_impl(pool, indexes, nr_bufs, nr_packets, len, burst,
                             nr_times);
}


static void test_write_and_read_single1(struct objpool* pool,
                                        uint32_t indexes[NR_BUFS])
{
    cerr << "start test_write_and_read_single1 ... " << endl;

    size_t len      = BUF_SIZE * 1;
    size_t burst    = 1;
    size_t nr_times = 100000;

    test_write_and_read(pool, indexes, len, burst, nr_times);

    cerr << "done" << endl;
}


static void test_write_and_read_single2(struct objpool* pool,
                                        uint32_t indexes[NR_BUFS])
{
    cerr << "start test_write_and_read_single2 ... " << endl;

    size_t len      = BUF_SIZE * 1;
    size_t burst    = 5;
    size_t nr_times = 100000;

    test_write_and_read(pool, indexes, len, burst, nr_times);

    cerr << "done" << endl;
}


static void test_write_and_read_single3(struct objpool* pool,
                                        uint32_t indexes[NR_BUFS])
{
    cerr << "start test_write_and_read_single3 ... " << endl;

    size_t len      = BUF_SIZE * 1;
    size_t burst    = NR_BUFS / 2;
    size_t nr_times = 100;

    test_write_and_read(pool, indexes, len, burst, nr_times);

    cerr << "done" << endl;
}


static void test_write_and_read_multi1(struct objpool* pool,
                                       uint32_t indexes[NR_BUFS])
{
    cerr << "start test_write_and_read_multi1 ... " << endl;

    size_t len      = BUF_SIZE * 4;
    size_t burst    = 1;
    size_t nr_times = 100000;

    test_write_and_read(pool, indexes, len, burst, nr_times);

    cerr << "done" << endl;
}


static void test_write_and_read_multi2(struct objpool* pool,
                                       uint32_t indexes[NR_BUFS])
{
    cerr << "start test_write_and_read_multi2 ... " << endl;

    size_t len      = BUF_SIZE * 4;
    size_t burst    = 10;
    size_t nr_times = 100000;

    test_write_and_read(pool, indexes, len, burst, nr_times);

    cerr << "done" << endl;
}


queue<uint32_t> g_idx_list;
mutex g_mtx;
condition_variable g_cv;


static void write_thread(struct objpool* pool, size_t required_size,
                         size_t actual_size, size_t nr_packets)
{
    cerr << "start writer thread (" << nr_packets << ")" << endl;

    size_t counter = 0;

    try {
        while (counter < nr_packets) {
            uint32_t index;

            uint8_t* packet = objpool_alloc_chunks(pool, required_size, &index);
            if (! packet) {
                g_cv.notify_one();
                this_thread::sleep_for(chrono::milliseconds(10));
                continue;
            }

            if (calc_nr_chunks(required_size) > calc_nr_chunks(actual_size)) {
                if (! objpool_trim_chunks(pool, index, required_size, actual_size)) {
                    throw runtime_error("Can't trim the packet: " + itos(index));
                }
            }

            //cerr << "write: " << counter << " (" << index << ")" << endl;

            g_mtx.lock();
            g_idx_list.push(index);
            g_mtx.unlock();

            g_cv.notify_one();

            counter++;
        }
    } catch (const exception& e) {
        cerr << "[writer] ERROR: " << e.what() << endl;
    }

    cerr << "stop writer thread  (" << counter << ")" << endl;
}


static void read_thread(struct objpool* pool, size_t actual_size, size_t nr_packets)
{
    cerr << "start reader thread (" << nr_packets << ")" << endl;

    size_t counter = 0;

    try {
        mutex wait_mtx;
        unique_lock<mutex> lck(wait_mtx);

        while (counter < nr_packets) {
            while (g_idx_list.empty()) {
                g_cv.wait(lck);
            }

            g_mtx.lock();
            uint32_t index = g_idx_list.front();
            g_idx_list.pop();
            g_mtx.unlock();

            uint8_t* packet = get_chunk_from_index(pool, index);
            if (! packet) {
                throw runtime_error("Can't get packet: " + itos(index));
            }

            //cerr << "read: " << counter << " (" << index << ")" << endl;

            objpool_release_chunks(pool, index, actual_size);

            counter++;
        }
    } catch (const exception& e) {
        cerr << "[reader] ERROR: " << e.what() << endl;
    }

    cerr << "stop reader thread (" << counter << ")" << endl;
}


static void test_concurrent_write_and_read1(struct objpool* pool)
{
    cerr << "start test_concurrent_write_and_read ... " << endl;

    size_t required_size = BUF_SIZE * 1;
    size_t actual_size   = BUF_SIZE * 1;
    size_t nr_packets    = 1000000;

    thread writer(write_thread, pool, required_size, actual_size, nr_packets);
    thread reader(read_thread, pool, actual_size, nr_packets);

    writer.join();
    reader.join();

    cerr << "done" << endl;
}


int main()
{
    struct objpool *pool = objpool_init("test_pktpool_up.dat", BUF_SIZE, NR_BUFS);
    if (! pool) {
        cerr << "ERROR: Can't initialize an objpool" << endl;
        return -1;
    }

    uint32_t indexes[NR_BUFS] = { 0 };

    try {
        test_single(pool, indexes);

        test_single_nonalign(pool, indexes);

        test_multi(pool, indexes);

        test_multi_nonalign1(pool, indexes);

        test_multi_nonalign2(pool, indexes);

        test_multi_nonalign3(pool, indexes);

        test_write_and_read_single1(pool, indexes);

        test_write_and_read_single2(pool, indexes);

        test_write_and_read_single3(pool, indexes);

        test_write_and_read_multi1(pool, indexes);

        test_write_and_read_multi2(pool, indexes);

        test_concurrent_write_and_read1(pool);
    } catch (const exception& e) {
        cerr << "ERROR: " << e.what() << endl;
    }

    objpool_exit(pool, true);

    return 0;
}
