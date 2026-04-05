/*
 * ZUPT - CLI v1.5.0
 * Multi-threaded compression, AES-256 encryption, progress bars
 */
#include "zupt.h"
#include "zupt_thread.h"
#include "zupt_cpuid.h"
#include "vaptvupt.h"  /* VAPTVUPT: codec ID */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <conio.h>
#else
  #include <termios.h>
#endif

static void banner(void) {
    fprintf(stderr,
        "Zupt %s - Next-Generation Compression Utility\n"
        "Format v%d.%d | Codec: Zupt-LZ | Checksum: XXH64\n"
        "Encryption: AES-256-CTR + HMAC-SHA256 | KDF: PBKDF2-SHA256\n\n",
        ZUPT_VERSION_STRING, ZUPT_FORMAT_MAJOR, ZUPT_FORMAT_MINOR);
}

static void usage(void) {
    banner();
    fprintf(stderr,
        "Usage:\n"
        "  zupt compress [OPTIONS] <output.zupt> <files/dirs...>\n"
        "  zupt extract  [OPTIONS] <archive.zupt>\n"
        "  zupt list     [OPTIONS] <archive.zupt>\n"
        "  zupt test     [OPTIONS] <archive.zupt>\n"
        "  zupt bench    <files/dirs...>          Compare levels 1-9\n"
        "  zupt keygen                            Key generation"
        "  zupt version\n"
        "  zupt help\n"
        "\n"
        "Compress Options:\n"
        "  -l, --level <1-9>     Compression level (default: 7)\n"
        "                          1-2: fast, small window\n"
        "                          3-5: balanced\n"
        "                          6-7: high compression (default)\n"
        "                          8-9: maximum, 1MB window, deep search\n"
        "  -b, --block <SIZE>    Block size in bytes (default: 128KB)\n"
        "  -s, --store           Store without compression\n"
        "  -f, --fast            Use fast LZ codec (less compression)\n"
        "  --vv, --vaptvupt      Use VaptVupt codec (fast LZ + ANS entropy)\n"
        "  --lzhp                Use Zupt-LZHP codec (LZ77+Huffman, no SIMD needed)\n"
        "  -p, --password <PW>   Encrypt with AES-256 (prompted if empty)\n"
        "  -v, --verbose         Verbose per-file output\n"
        "  -t, --threads <N>     Thread count (0=auto, 1=single, 2-64=explicit)\n"
        "\n"
        "Extract/List/Test Options:\n"
        "  -o, --output <DIR>    Output directory (extract only)\n"
        "  -p, --password <PW>   Decryption password\n"
        "  -pq,--post-quantum    Post-quantum Encryption|Decryption \n"
        "  -v, --verbose         Verbose output\n"
        "  -t, --threads <N>     Thread count for decompression\n"
        "\n"
        "Directories are traversed recursively.\n"
        "\n"
        "Examples:\n"
        "  zupt keygen -o mykey.key                               # Generate keypair\n"
        "  zupt keygen --pub -o pub.key -k mykey.key              # Export public key\n"
        "  zupt compress --pq pub.key backup.zupt ~/Documents/    # Encrypt with public key\n" 
        "  zupt extract --pq mykey.key -o ~/restored/ backup.zupt # Decrypt with private key\n"
        "  zupt compress backup.zupt ~/Documents/                 # Compress (without password)\n" 
        "  zupt compress -l 9 -p mysecret secure.zupt data/       # High Compression with password\n"
        "  zupt list secure.zupt -p mysecret                      # List\n"
        "  zupt extract -o restored/ -p mysecret secure.zupt      # Extract with password\n"
        "  zupt bench ~/Documents/                                # Benchmark\n"
        "\n"
        "Compression: LZ77 (1MB window) + Huffman entropy coding\n"
        "Security:    AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC)\n"
        "KDF:         PBKDF2-SHA256 (600,000 iterations)\n"
        "\n"
        "License: MIT\n"
    );
}

/* Securely prompt for password (hide input) */
static void prompt_password(const char *prompt, char *buf, size_t cap) {
    fprintf(stderr, "%s", prompt);
#ifdef _WIN32
    size_t i = 0;
    while (i < cap - 1) {
        int c = _getch();
        if (c == '\r' || c == '\n') break;
        if (c == '\b' && i > 0) { i--; continue; }
        buf[i++] = (char)c;
    }
    buf[i] = '\0';
    fprintf(stderr, "\n");
#else
    struct termios old, new_t;
    tcgetattr(0, &old);
    new_t = old;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(0, TCSANOW, &new_t);
    if (fgets(buf, (int)cap, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    }
    tcsetattr(0, TCSANOW, &old);
    fprintf(stderr, "\n");
#endif
}

static int streq(const char *a, const char *b) { return strcmp(a,b)==0; }
static int isopt(const char *a) { return a[0]=='-'; }

int main(int argc, char **argv) {
    /* Detect CPU features (AES-NI, AVX2) at startup */
    zupt_detect_cpu(&zupt_cpu);

    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (streq(cmd,"help")||streq(cmd,"--help")||streq(cmd,"-h")) { usage(); return 0; }
    if (streq(cmd,"version")||streq(cmd,"--version")||streq(cmd,"-V")) {
        printf("zupt %s\nFormat: v%d.%d\nCodec: Zupt-LZ (0x%04X)\n"
               "Encryption: AES-256-CTR+HMAC-SHA256\nKDF: PBKDF2-SHA256 (%d iter)\n",
               ZUPT_VERSION_STRING, ZUPT_FORMAT_MAJOR, ZUPT_FORMAT_MINOR,
               ZUPT_CODEC_ZUPT_LZ, ZUPT_KDF_ITERATIONS);
        return 0;
    }

    /* ─── compress ─── */
    if (streq(cmd,"compress")||streq(cmd,"c")) {
        zupt_options_t opts; zupt_default_options(&opts);
        int ai = 2;
        while (ai<argc && isopt(argv[ai])) {
            if ((streq(argv[ai],"-l")||streq(argv[ai],"--level"))&&ai+1<argc) {
                opts.level=atoi(argv[++ai]); if(opts.level<1)opts.level=1; if(opts.level>9)opts.level=9;
            } else if ((streq(argv[ai],"-b")||streq(argv[ai],"--block"))&&ai+1<argc) {
                opts.block_size=(uint32_t)atol(argv[++ai]);
                if(opts.block_size<ZUPT_MIN_BLOCK_SZ)opts.block_size=ZUPT_MIN_BLOCK_SZ;
                if(opts.block_size>ZUPT_MAX_BLOCK_SZ)opts.block_size=ZUPT_MAX_BLOCK_SZ;
            } else if (streq(argv[ai],"-s")||streq(argv[ai],"--store")) {
                opts.codec_id=ZUPT_CODEC_STORE;
            } else if (streq(argv[ai],"-f")||streq(argv[ai],"--fast")) {
                opts.codec_id=ZUPT_CODEC_ZUPT_LZ;
            } else if (streq(argv[ai],"--vv")||streq(argv[ai],"--vaptvupt")) {
                opts.codec_id=ZUPT_CODEC_VAPTVUPT; /* VAPTVUPT */
            } else if (streq(argv[ai],"--lzhp")) {
                opts.codec_id=ZUPT_CODEC_ZUPT_LZHP;
            } else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) {
                    strncpy(opts.password, argv[++ai], sizeof(opts.password)-1);
                } else {
                    prompt_password("Password: ", opts.password, sizeof(opts.password));
                    char confirm[256];
                    prompt_password("Confirm:  ", confirm, sizeof(confirm));
                    if (strcmp(opts.password, confirm)!=0) {
                        fprintf(stderr, "Error: Passwords do not match.\n"); return 1;
                    }
                }
            } else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) {
                opts.verbose=1;
            } else if (streq(argv[ai],"--solid")||streq(argv[ai],"-S")) {
                opts.solid=1;
            } else if ((streq(argv[ai],"-t")||streq(argv[ai],"--threads"))&&ai+1<argc) {
                opts.threads=atoi(argv[++ai]);
                if(opts.threads<0)opts.threads=0;
                if(opts.threads>ZUPT_MAX_THREADS)opts.threads=ZUPT_MAX_THREADS;
            } else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            } else {
                fprintf(stderr,"Error: Unknown option '%s'\n",argv[ai]); return 1;
            }
            ai++;
        }
        if (argc-ai<2) {
            fprintf(stderr,"Error: compress requires <output.zupt> <files/dirs...>\n"); return 1;
        }
        const char *output = argv[ai++];

        /* Collect files (expand directories recursively) */
        zupt_filelist_t fl; zupt_filelist_init(&fl);
        for (int i=ai; i<argc; i++)
            zupt_collect_files(&fl, argv[i], argv[i]);

        if (fl.count == 0) {
            fprintf(stderr, "Error: No files found.\n");
            zupt_filelist_free(&fl); return 1;
        }

        banner();

        /* Resolve thread count */
        opts.threads = zupt_resolve_threads(opts.threads);
        if (opts.solid && opts.threads > 1) {
            fprintf(stderr, "  Note: solid mode is single-threaded (cross-file LZ context)\n");
            opts.threads = 1;
        }

        /* Resolve AUTO codec based on hardware detection */
        if (opts.codec_id == ZUPT_CODEC_AUTO)
            opts.codec_id = zupt_resolve_auto_codec();

        fprintf(stderr, "  Collected %d file(s) for compression%s\n", fl.count,
                opts.solid ? " (SOLID MODE)" : "");
        if (opts.threads > 1)
            fprintf(stderr, "  Threads: %d\n", opts.threads);
        if (opts.encrypt) fprintf(stderr, "  Encryption: ENABLED\n");
        fprintf(stderr, "\n");

        zupt_error_t err;
        if (opts.solid) {
            err = zupt_compress_solid(output,
                (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
        } else {
            err = zupt_compress_files(output,
                (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
        }
        zupt_filelist_free(&fl);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── extract ─── */
    if (streq(cmd,"extract")||streq(cmd,"x")) {
        zupt_options_t opts; zupt_default_options(&opts);
        const char *outdir = NULL;
        int ai = 2;
        while (ai<argc && isopt(argv[ai])) {
            if ((streq(argv[ai],"-o")||streq(argv[ai],"--output"))&&ai+1<argc)
                outdir = argv[++ai];
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else prompt_password("Password: ", opts.password, sizeof(opts.password));
            } else if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) opts.verbose=1;
            else if ((streq(argv[ai],"-t")||streq(argv[ai],"--threads"))&&ai+1<argc) {
                opts.threads=atoi(argv[++ai]);
                if(opts.threads<0)opts.threads=0;
                if(opts.threads>ZUPT_MAX_THREADS)opts.threads=ZUPT_MAX_THREADS;
            }
            else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (ai>=argc) { fprintf(stderr,"Error: extract requires <archive.zupt>\n"); return 1; }
        banner();
        zupt_error_t err = zupt_extract_archive(argv[ai], outdir, &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── list ─── */
    if (streq(cmd,"list")||streq(cmd,"l")) {
        zupt_options_t opts; zupt_default_options(&opts);
        int ai = 2;
        while (ai<argc && isopt(argv[ai])) {
            if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) opts.verbose=1;
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else prompt_password("Password: ", opts.password, sizeof(opts.password));
            }
            else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (ai>=argc) { fprintf(stderr,"Error: list requires <archive.zupt>\n"); return 1; }
        zupt_error_t err = zupt_list_archive(argv[ai], &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── test ─── */
    if (streq(cmd,"test")||streq(cmd,"t")) {
        zupt_options_t opts; zupt_default_options(&opts);
        int ai = 2;
        while (ai<argc && isopt(argv[ai])) {
            if (streq(argv[ai],"-v")||streq(argv[ai],"--verbose")) opts.verbose=1;
            else if (streq(argv[ai],"-p")||streq(argv[ai],"--password")) {
                opts.encrypt=1;
                if (ai+1<argc && !isopt(argv[ai+1])) strncpy(opts.password,argv[++ai],sizeof(opts.password)-1);
                else prompt_password("Password: ", opts.password, sizeof(opts.password));
            }
            else if (streq(argv[ai],"--pq")&&ai+1<argc) {
                opts.pq_mode=1; opts.encrypt=1;
                strncpy(opts.keyfile, argv[++ai], sizeof(opts.keyfile)-1);
            }
            else { fprintf(stderr,"Unknown option '%s'\n",argv[ai]); return 1; }
            ai++;
        }
        if (ai>=argc) { fprintf(stderr,"Error: test requires <archive.zupt>\n"); return 1; }
        banner();
        zupt_error_t err = zupt_test_archive(argv[ai], &opts);
        zupt_secure_wipe(opts.password, sizeof(opts.password));
        return err==ZUPT_OK ? 0 : 1;
    }

    /* ─── bench ─── */
    if (streq(cmd,"bench")||streq(cmd,"b")) {
        int ai = 2;
        int compare_mode = 0;
        if (ai < argc && streq(argv[ai], "--compare")) { compare_mode = 1; ai++; }

        if (!compare_mode && ai >= argc) { fprintf(stderr, "Error: bench requires <files/dirs...> or --compare\n"); return 1; }

        /* Generate corpus if --compare with no files */
        char gen_dir[256] = {0};
        if (compare_mode && ai >= argc) {
            snprintf(gen_dir, sizeof(gen_dir), "/tmp/zupt_bench_corpus_%d", (int)getpid());
            zupt_mkdir(gen_dir);
            char p[512]; FILE *gf;
            snprintf(p, sizeof(p), "%s/text.txt", gen_dir);
            gf = fopen(p, "wb");
            if (gf) { for (int i=0;i<15000;i++) fprintf(gf, "The quick brown fox jumps over the lazy dog. Line %d value %d.\n", i, i*17%997); fclose(gf); }
            snprintf(p, sizeof(p), "%s/data.json", gen_dir);
            gf = fopen(p, "wb");
            if (gf) { for (int i=0;i<12000;i++) fprintf(gf, "{\"id\":%d,\"name\":\"user_%d\",\"score\":%d}\n", i, i, i*31%1000); fclose(gf); }
            snprintf(p, sizeof(p), "%s/records.csv", gen_dir);
            gf = fopen(p, "wb");
            if (gf) { fprintf(gf,"id,name,score\n"); for (int i=0;i<14000;i++) fprintf(gf,"%d,user_%d,%d\n", i, i, i*17%100); fclose(gf); }
            snprintf(p, sizeof(p), "%s/random.bin", gen_dir);
            gf = fopen(p, "wb");
            if (gf) { uint8_t rb[4096]; for (int i=0;i<64;i++){zupt_random_bytes(rb,sizeof(rb));fwrite(rb,1,sizeof(rb),gf);} fclose(gf); }
            /* Use gen_dir as the input path — need a writable argv slot */
            static char gen_arg[256];
            strncpy(gen_arg, gen_dir, sizeof(gen_arg)-1);
            gen_arg[sizeof(gen_arg)-1] = '\0';
            argv[argc] = gen_arg;
            ai = argc; argc++;
        }

        zupt_filelist_t fl; zupt_filelist_init(&fl);
        for (int i = ai; i < argc; i++)
            zupt_collect_files(&fl, argv[i], argv[i]);
        if (fl.count == 0) { fprintf(stderr, "No files found.\n"); zupt_filelist_free(&fl); return 1; }

        uint64_t total_in = 0;
        for (int i = 0; i < fl.count; i++) {
            FILE *tf = fopen(fl.paths[i], "rb");
            if (tf) { fseek(tf, 0, SEEK_END); total_in += (uint64_t)ftell(tf); fclose(tf); }
        }
        char isz[32]; zupt_format_size(total_in, isz, sizeof(isz));
        banner();

        if (compare_mode) {
            fprintf(stderr, "  Codec Comparison — %d file(s), %s\n\n", fl.count, isz);
            fprintf(stderr, "  %-20s %12s %12s %10s\n", "Codec", "Compress", "Decompress", "Ratio");
            fprintf(stderr, "  ────────────────────────────────────────────────────────────\n");

            char tmp_path[256], tmp_out[256];
            snprintf(tmp_path, sizeof(tmp_path), "/tmp/zupt_cmp_%d.zupt", (int)getpid());
            snprintf(tmp_out, sizeof(tmp_out), "/tmp/zupt_cmp_out_%d", (int)getpid());

            struct { const char *name; uint16_t codec; int level; } codecs[] = {
                {"VaptVupt UF",  ZUPT_CODEC_VAPTVUPT, 1},
                {"VaptVupt BAL", ZUPT_CODEC_VAPTVUPT, 5},
                {"VaptVupt EXT", ZUPT_CODEC_VAPTVUPT, 9},
                {"Zupt-LZHP",    ZUPT_CODEC_ZUPT_LZHP,7},
                {"Zupt-LZ",      ZUPT_CODEC_ZUPT_LZ,  5},
            };
            int ncodecs = (int)(sizeof(codecs)/sizeof(codecs[0]));

            for (int ci = 0; ci < ncodecs; ci++) {
                zupt_options_t opts; zupt_default_options(&opts);
                opts.codec_id = codecs[ci].codec; opts.level = codecs[ci].level; opts.quiet = 1;

                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                zupt_error_t cerr = zupt_compress_files(tmp_path,
                    (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double csec = (double)(t1.tv_sec-t0.tv_sec)+(double)(t1.tv_nsec-t0.tv_nsec)/1e9;
                if (csec < 0.001) csec = 0.001;

                if (cerr != ZUPT_OK) { fprintf(stderr, "  %-20s  FAILED\n", codecs[ci].name); continue; }

                FILE *zf = fopen(tmp_path, "rb"); uint64_t zsize = 0;
                if (zf) { fseek(zf,0,SEEK_END); zsize=(uint64_t)ftell(zf); fclose(zf); }

                zupt_options_t dopts; zupt_default_options(&dopts); dopts.quiet = 1;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                zupt_extract_archive(tmp_path, tmp_out, &dopts);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double dsec = (double)(t1.tv_sec-t0.tv_sec)+(double)(t1.tv_nsec-t0.tv_nsec)/1e9;
                if (dsec < 0.001) dsec = 0.001;

                fprintf(stderr, "  %-20s %9.1f MB/s %9.1f MB/s %8.2f:1\n",
                    codecs[ci].name, (double)total_in/csec/1048576.0,
                    (double)total_in/dsec/1048576.0,
                    total_in>0&&zsize>0?(double)total_in/(double)zsize:1.0);

                char rm[512]; snprintf(rm,sizeof(rm),"rm -rf '%s'",tmp_out); if (system(rm)) { /* ignore */ }
                remove(tmp_path);
            }

            /* External tools */
            fprintf(stderr, "  ────────────────────────────────────────────────────────────\n");
            char concat[256];
            snprintf(concat, sizeof(concat), "/tmp/zupt_cmp_cat_%d", (int)getpid());
            FILE *cf = fopen(concat, "wb");
            if (cf) {
                for (int i=0;i<fl.count;i++){FILE*inf=fopen(fl.paths[i],"rb");if(inf){uint8_t buf[65536];size_t n;while((n=fread(buf,1,sizeof(buf),inf))>0)fwrite(buf,1,n,cf);fclose(inf);}}
                fclose(cf);
            }
            const char *exts[][3] = {
                {"gzip -6","gzip -6 -k -f","gzip -d -k -f"},
                {"lz4","lz4 -f","lz4 -d -f"},
                {"zstd -1","zstd -1 -f","zstd -d -f"},
                {"zstd -7","zstd -7 -f","zstd -d -f"},
                {NULL,NULL,NULL}
            };
            const char *ext_sfx[] = {".gz",".lz4",".zst",".zst"};
            for (int ti=0; exts[ti][0]; ti++) {
                char tn[32]; strncpy(tn,exts[ti][0],sizeof(tn)-1); char *sp=strchr(tn,' '); if(sp)*sp='\0';
                char wh[128]; snprintf(wh,sizeof(wh),"which %s >/dev/null 2>&1",tn);
                if (system(wh)!=0) continue;

                char co[256]; snprintf(co,sizeof(co),"%s%s",concat,ext_sfx[ti]);
                remove(co);
                char ccmd[512]; snprintf(ccmd,sizeof(ccmd),"%s %s >/dev/null 2>&1",exts[ti][1],concat);
                struct timespec t0,t1;
                clock_gettime(CLOCK_MONOTONIC,&t0); if (system(ccmd)) { /* ignore */ } clock_gettime(CLOCK_MONOTONIC,&t1);
                double csec=(double)(t1.tv_sec-t0.tv_sec)+(double)(t1.tv_nsec-t0.tv_nsec)/1e9; if(csec<0.001)csec=0.001;
                FILE*ef=fopen(co,"rb"); uint64_t esz=0; if(ef){fseek(ef,0,SEEK_END);esz=(uint64_t)ftell(ef);fclose(ef);}

                char dcmd[512]; snprintf(dcmd,sizeof(dcmd),"%s %s >/dev/null 2>&1",exts[ti][2],co);
                clock_gettime(CLOCK_MONOTONIC,&t0); if (system(dcmd)) { /* ignore */ } clock_gettime(CLOCK_MONOTONIC,&t1);
                double dsec=(double)(t1.tv_sec-t0.tv_sec)+(double)(t1.tv_nsec-t0.tv_nsec)/1e9; if(dsec<0.001)dsec=0.001;

                fprintf(stderr, "  %-20s %9.1f MB/s %9.1f MB/s %8.2f:1\n",
                    exts[ti][0], (double)total_in/csec/1048576.0, (double)total_in/dsec/1048576.0,
                    total_in>0&&esz>0?(double)total_in/(double)esz:1.0);
                remove(co); char dec[512]; snprintf(dec,sizeof(dec),"%s.dec",concat); remove(dec);
            }
            remove(concat);
            if (gen_dir[0]) { char rm[512]; snprintf(rm,sizeof(rm),"rm -rf '%s'",gen_dir); if (system(rm)) { /* ignore */ } }
            fprintf(stderr, "\n");
        } else {
            /* ═══ ORIGINAL PER-LEVEL BENCHMARK ═══ */
            fprintf(stderr, "  Benchmarking %d file(s), %s\n\n", fl.count, isz);
            fprintf(stderr, "  %-7s %12s %10s %10s %10s\n", "Level", "Compressed", "Ratio", "%", "Speed");
            fprintf(stderr, "  ─────────────────────────────────────────────────────────\n");

            char tmp_path[256];
            snprintf(tmp_path, sizeof(tmp_path), "/tmp/zupt_bench_%d.zupt", (int)getpid());

            for (int lvl = 1; lvl <= 9; lvl++) {
                zupt_options_t opts; zupt_default_options(&opts);
                opts.level = lvl;
                opts.verbose = 0;
                opts.quiet = 1;

                time_t t0 = time(NULL);
                zupt_error_t err = zupt_compress_files(tmp_path,
                    (const char**)fl.arc_paths, (const char**)fl.paths, fl.count, &opts);
                time_t elapsed = time(NULL) - t0;
                if (elapsed < 1) elapsed = 1;

                if (err == ZUPT_OK) {
                    FILE *zf = fopen(tmp_path, "rb");
                    uint64_t zsize = 0;
                    if (zf) { fseek(zf, 0, SEEK_END); zsize = (uint64_t)ftell(zf); fclose(zf); }

                    char csz[32]; zupt_format_size(zsize, csz, sizeof(csz));
                    double ratio = total_in > 0 ? (double)total_in / (double)zsize : 1.0;
                    double pct = total_in > 0 ? (double)zsize / (double)total_in * 100.0 : 100.0;
                    double speed = (double)total_in / (double)elapsed / 1048576.0;

                    fprintf(stderr, "  %-7d %12s %9.2f:1 %9.1f%% %8.1f MB/s\n",
                            lvl, csz, ratio, pct, speed);
                } else {
                    fprintf(stderr, "  %-7d %12s\n", lvl, "FAILED");
                }
                remove(tmp_path);
            }
            fprintf(stderr, "\n");
        }

        zupt_filelist_free(&fl);
        return 0;
    }

    /* ─── keygen ─── */
    if (streq(cmd,"keygen")) {
        const char *outfile = NULL;
        const char *privfile = NULL;
        int export_pub = 0;
        int ai = 2;
        while (ai < argc && isopt(argv[ai])) {
            if ((streq(argv[ai],"-o")||streq(argv[ai],"--output")) && ai+1 < argc)
                outfile = argv[++ai];
            else if ((streq(argv[ai],"-k")||streq(argv[ai],"--key")) && ai+1 < argc)
                privfile = argv[++ai];
            else if (streq(argv[ai],"--pub"))
                export_pub = 1;
            else { fprintf(stderr, "Unknown option '%s'\n", argv[ai]); return 1; }
            ai++;
        }

        if (!outfile) {
            fprintf(stderr, "Error: keygen requires -o <output_file>\n");
            fprintf(stderr, "  zupt keygen -o keyfile.key           # Generate keypair\n");
            fprintf(stderr, "  zupt keygen --pub -o pub.key -k priv.key  # Export public key\n");
            return 1;
        }

        banner();
        if (export_pub) {
            if (!privfile) { fprintf(stderr, "Error: --pub requires -k <private_keyfile>\n"); return 1; }
            fprintf(stderr, "  Exporting public key from: %s\n", privfile);
            if (zupt_hybrid_export_pubkey(privfile, outfile) != 0) {
                fprintf(stderr, "Error: Failed to export public key.\n"); return 1;
            }
            fprintf(stderr, "  Public key written to: %s\n", outfile);
        } else {
            fprintf(stderr, "  Generating ML-KEM-768 + X25519 keypair...\n");
            if (zupt_hybrid_keygen(outfile) != 0) {
                fprintf(stderr, "Error: Key generation failed.\n"); return 1;
            }
            fprintf(stderr, "  Private key written to: %s\n", outfile);
            fprintf(stderr, "  SECURITY: Keep this file secret. Back it up securely.\n");
            fprintf(stderr, "  To export public key: zupt keygen --pub -o pub.key -k %s\n", outfile);
        }
        return 0;
    }

    fprintf(stderr, "Unknown command '%s'. Run 'zupt help'.\n", cmd);
    return 1;
}
