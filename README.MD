## PAPPCA使用教程

#### 使用前编写根目录下的 papp.yaml 文件

```yaml
# the number of papps
PAPPNumber: 2
# PAPP list
PAPPs:
  # PAPP name
  - PAPP:
    # the PAPP information to generate cert
    PAPPName:            "PAPP-A"
    Country:             "china"
    Organization:        "buaa"
    OrganizationalUnit:  "www.buaa.edu.cn"
    Province:            "beijing"
    Locality:            "haidian"
    StreetAddress:       "37"

  - PAPP:
    PAPPName:            "PAPP-B"
    Country:             "china"
    Organization:        "hangtianxinxi"
    OrganizationalUnit:  "www.hangtianxinxi.com"
    Province:            "beijing"
    Locality:            "caoyang"
    StreetAddress:       "73"
```

注意：PAPP的证书保存在"./crypto/PAPPs/"目录下，由PAPPName区分；超级链证书保存在"./crypto/superchain/"目录下；

#### PAPPCA程序使用命令

```bash
./pappca -cmd init          # 生成超级链根证书和私钥
./pappca -cmd generate      # 生成yaml文件中所有PAPP的证书和私钥
```

1. ./pappca -cmd generate 必须在超级链证书和私钥已经存在的情况下执行；

2. ./pappca -cmd init 执行会删除原有的超级链证书和私钥，建议只初始化时使用；

#### 添加新的PAPP

当有新的PAPP加入时，修改papp.yaml为该PAPP的信息，PAPP的名称不能重复，再使用命令./pappca -cmd generate，即可为新的PAPP生成证书和私钥。