# typora-s3

CLI tool to upload object to s3-compatible storage backend and set `download` policy for it.

## Build

```bash
$ git clone https://github.com/fengxsong/typora-s3.git
$ cd typora-s3
$ CGO_ENABLE=0 go build -o typora-s3 typora-s3.go
```

## Configuration

configuration can be set by YAML file, environment variables and command line flags. for example.

```bash
$ cat $HOME/.typora-s3.yaml
endpoint: $s3addr
accessKey: $AK
secretKey: $SK
useSsl: true
hashAlg: md5
$ # or get flags from help usage
$ go run typora-s3.go -h
```

## integrate with typora editor

![integrate-with-typora](https://github.com/fengxsong/typora-s3/blob/main/images/integrate-with-typora.png)

## Contributions

PR and issues are welcome!
