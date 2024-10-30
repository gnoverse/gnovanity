# gnovanity

A tool to generate gno vanity addresses, like <code><b>g1m0rgan</b>0qndpsl43f6es7n8gnutx5cvm466flss</code>.

```console
$ go install github.com/gnoverse/gnovanity@latest
$ gnovanity -h
Usage of gnovanity:
  -cpuprofile file
        write cpu profile to file
  -pattern string
        regexp to filter results (default "^g100")
  -print-stats
        print perf stats every 10s
  -threads int
        number of threads (default 16)
```

Configure `-pattern` to specify what you'd like to address to look like, and use
`-threads` to configure how much of your machine threads to use (defaults to
GOMAXPROCS).
