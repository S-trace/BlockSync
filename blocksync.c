#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <getopt.h>

#define BLOCK_SIZE (4*1024*1024) // 4MiB
#define DIGEST_METHOD GCRY_MD_SHA512
#define FALSE (0)
#define TRUE (!FALSE)

struct globalArgs_t {
    char *origin;    /* параметр -o */
    char *target;    /* параметр -t */
    char *digest;    /* параметр -d */
    int fast;        /* параметр -f */
} globalArgs;

static const char *optString = "o:t:d:fh?";

static const struct option longOpts[] = {
  { "origin", required_argument, NULL, 'o' },
  { "target", required_argument, NULL, 't' },
  { "digest", required_argument, NULL, 'd' },
  { "fast", no_argument, NULL, 'f' },
  { "help", no_argument, NULL, 'h' },
  { NULL, no_argument, NULL, 0 }
};

void usage(char **argv) {
  printf("Usage: %s --origin=origin_device --target=target_device --digest=digest_file [--fast] [--help]\n", argv[0]);
  printf("--origin=origin_device, -o origin_device\n");
  printf("  Source device (which will be backed up)\n");
  printf("--target=target_device, -t target_device\n");
  printf("  Target device (which will be updated during backup)\n");
  printf("--digest=digest_file, -d digest_file\n");
  printf("  Digest file (will be created/updated, may be used with --fast option)\n");
  printf("  If digest file is not exist - it will be created\n");
  printf("  If digest file is exist - it must match length of devices, or will be truncated to appropriate size\n");
  printf("--fast, -f\n");
  printf("  Use digest file to check was block changed or not\n");
  printf("  Do not read target_device blocks - read source blocks only and then check digest of each block from digest file\n");
  printf("  Use this only when sure that target image was not modified since last backup\n");
  printf("--help, -h\n");
  printf("  Show this message and exit\n");
}

void parse_options(int argc, char **argv) {
  int longIndex;
  int opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
  while( opt != -1 ) {
    switch( opt ) {
      case 'o':
        globalArgs.origin = optarg; /* true */
        break;
      case 't':
        globalArgs.target = optarg;
        break;
      case 'd':
        globalArgs.digest = optarg;
        break;
      case 'f':
        globalArgs.fast = TRUE;
        break;
      case 'h':   /* намеренный проход в следующий case-блок */
      case '?':
        usage(argv);
        exit(EXIT_SUCCESS);
        break;
      case 0:     /* длинная опция без короткого эквивалента */
//         if( strcmp( "randomize", longOpts[longIndex].name ) == 0 ) {
//           globalArgs.randomized = 1;
//         }
        usage(argv);
        exit(EXIT_FAILURE);
        break;
      default:
        /* сюда попасть невозможно. */
        break;
    }
    opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
  }
}

int main(int argc, char **argv) {
    int res = EXIT_FAILURE;
    size_t block_size = BLOCK_SIZE;
    int origin_fd = -1;
    int target_fd = -1;
    int digest_fd = -1;
    char *origin_data = NULL;
    char *target_data = NULL;
    char *digest_data = NULL;
    off_t origin_size = 0;
    off_t target_size = 0;
    size_t digest_size = 0;
    off_t data_len = 0;
    int have_digest_data = FALSE;
    size_t current_block = 0;
    size_t blocks_count = 0;
    unsigned int digest_length = gcry_md_get_algo_dlen(DIGEST_METHOD);
    unsigned char *origin_digest = (unsigned char*) malloc(digest_length);
    if (origin_digest == NULL) {
      printf("Error: Unable to allocate %u bytes for digest buffer :%s\n", digest_length, strerror(errno));
      goto error4;
    }
    printf("digest_length=%u\n", digest_length);

    parse_options(argc, argv);
    if (!globalArgs.origin || !globalArgs.target || !globalArgs.digest) {
      printf("Error: You must specify origin, target and digest names\n");
      usage(argv);
      exit(EXIT_FAILURE);
    }
    if (argc < 4) {
      usage(argv);
      exit(EXIT_FAILURE);
    }
    origin_fd = open(globalArgs.origin, O_RDONLY);
    if (origin_fd < 0) {
      printf("Unable to open origin_device \"%s\": %s\n", globalArgs.origin, strerror(errno));
      exit(EXIT_FAILURE);
    }

    target_fd = open(globalArgs.target, O_RDWR);
    if (target_fd < 0) {
      printf("Unable to open target_device \"%s\": %s\n", globalArgs.target, strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (access(globalArgs.digest, F_OK) != 0) {
      have_digest_data = TRUE;
    }
    digest_fd = open(globalArgs.digest, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (digest_fd < 0) {
      printf("Unable to open digest file \"%s\": %s\n", globalArgs.digest, strerror(errno));
      goto error3;
    }

    origin_size = lseek(origin_fd, 0, SEEK_END);
    lseek(origin_fd, 0, SEEK_SET);
    target_size = lseek(target_fd, 0, SEEK_END);
    lseek(target_fd, 0, SEEK_SET);
    data_len = origin_size < target_size ? origin_size : target_size;
    blocks_count = data_len / BLOCK_SIZE; // number of FULL blocks in data_len (maybe there is a tail also)

    origin_data = (char *)mmap(NULL, data_len, PROT_READ, MAP_SHARED, origin_fd, 0);
    if (MAP_FAILED == origin_data) {
      perror("Unable to mmap() origin_device");
      goto error1;
    }

    target_data = (char *)mmap(NULL, data_len, PROT_READ|PROT_WRITE, MAP_SHARED, target_fd, 0);
    if (MAP_FAILED == target_data) {
      perror("Unable to mmap() target_device");
      goto error2;
    }

    digest_size = (blocks_count+1) * digest_length;
    ftruncate(digest_fd, digest_size);
    digest_data = (char *)mmap(NULL, digest_size, PROT_READ|PROT_WRITE, MAP_SHARED, digest_fd, 0);
    if (MAP_FAILED == digest_data) {
      perror("Unable to mmap() digest file");
      goto error4;
    }
    sync();
    block_size = BLOCK_SIZE < data_len ? BLOCK_SIZE : data_len;
    printf("Starting\n");

    while (current_block <= blocks_count) {
      size_t offset = current_block * block_size;
      if ((offset + block_size) > data_len) {
        block_size = data_len - offset;
        if (block_size == 0) {
//           printf("block_size=%zu\n", block_size);
          break;
        }
        printf("Last block have size %zu (offset=%zu)\n", block_size, offset);
      }
      char *digest_offset = digest_data + (current_block * digest_length);
      gcry_md_hash_buffer(DIGEST_METHOD, origin_digest, origin_data + offset, block_size);
      int digest_matched = FALSE;
      if (memcmp(digest_offset, origin_digest, digest_length) == 0) {
        printf("Block %zu digest matched\n", current_block);
        digest_matched = TRUE;
      }
      if ((!digest_matched) && (0 != memcmp(target_data + offset, origin_data + offset, block_size))) {
        printf("Block %zu data mismatched, writing\n", current_block);
        memcpy(target_data + offset, origin_data + offset, block_size);
        msync(target_data, data_len, MS_SYNC);
      }
      if (!digest_matched) {
        printf("Block %zu digest mismatched, writing\n", current_block);
        memcpy(digest_offset, origin_digest, digest_length);
        msync(digest_data, digest_size, MS_SYNC);
      }
      ++current_block;
    }
    free(origin_digest);
    printf("Syncing\n");
    sync();
    res = EXIT_SUCCESS;
//     printf("Unmapping digest_data\n");
    munmap(digest_data, digest_size);
    error4:
//     printf("Unmapping target_data\n");
    munmap(target_data, data_len);
    error2:
//     printf("Unmapping origin_data\n");
    munmap(origin_data, data_len);
//     printf("Closing files\n");
    close(digest_fd);
    error3:
    close(target_fd);
    error1:
    close(origin_fd);
    exit(res);
}
