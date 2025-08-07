## x-ui-pro (x-ui + nginx) modification of https://github.com/mozaroc/x-ui-pro

- Modifications:
  - Auto install panel AmneziaWG Easy
  - Clean script and nginx config
  - Removed subpages
  - Removed sub2sing-box

- Auto Installation (lightweight)
- Auto SSL renewal / Daily reload Nginx X-ui
- Handle **REALITY** via **nginx**.
- Multi-user and config via port **443**
- Auto enabled subscriptions via port **443**
- Auto configured VLESS+Reality
- Auto configured Firewall
- More security and low detection with nginx
- Compatible with Cloudflare (only for WebSocket/GRPC)
- Random 150+ fake template!
- Linux Debian12/Ubuntu24!
  >

**Docker required for AmneziaWG Easy**

**You need two domains or subdomains**
  1. For panel and WebSocket/GRPC/HttpUgrade/SplitHttp
  2. For REALITY destination
  >
  Get Free subdomains - https://scarce-hole-1e2.notion.site/14d1666462e48069818cf42553bfae1f?pvs=74
  >
  RU instruction - https://scarce-hole-1e2.notion.site/3X-UI-pro-with-REALITY-panel-and-inbaunds-on-port-443-10d1666462e48085be0fee4c136ce417
  
➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖

### Install X-UI-PRO and AmneziaWG Easy

```
bash <(wget -qO- https://github.com/anton111111/x-ui-pro/raw/master/x-ui-pro.sh) -install yes -panel 1 -ONLY_CF_IP_ALLOW no
```
> 
> Do not change SubDomain for renew SSL❗


**Uninstall X-UI-PRO**:x:
```
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/anton111111/x-ui-pro/master/x-ui-pro.sh) -uninstall yes"
```

**backup panel and nginx configs**:x:
```
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/anton111111/x-ui-pro/master/backup.sh)"
```

