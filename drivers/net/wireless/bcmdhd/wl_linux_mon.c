/*
 * Broadcom Dongle Host Driver (DHD), Linux monitor network interface
 *
 * Copyright (C) 1999-2013, Broadcom Corporation
 * 
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 * 
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 * 
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 * $Id: dhd_linux_mon.c 280623 2011-08-30 14:49:39Z $
 */

#include <osl.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/ieee80211.h>
#include <linux/rtnetlink.h>
#include <net/ieee80211_radiotap.h>
#include <net/cfg80211.h>

#include <wlioctl.h>
#include <bcmutils.h>
#include <dhd_dbg.h>
#include <bcmendian.h>
#include <dngl_stats.h>
#include <dhd.h>

#ifdef PROP_TXSTATUS
#include <wlfc_proto.h>
#include <dhd_wlfc.h>
#endif /* PROP_TXSTATUS */


typedef enum monitor_states
{
	MONITOR_STATE_DEINIT = 0x0,
	MONITOR_STATE_INIT = 0x1,
	MONITOR_STATE_INTERFACE_ADDED = 0x2,
	MONITOR_STATE_INTERFACE_DELETED = 0x4
} monitor_states_t;
int dhd_add_monitor(char *name, struct net_device **new_ndev);
extern int dhd_start_xmit(struct sk_buff *skb, struct net_device *net);
int dhd_del_monitor(struct net_device *ndev);
int dhd_monitor_init(void *dhd_pub);
int dhd_monitor_uninit(void);

/**
 * Local declarations and defintions (not exposed)
 */
#ifndef DHD_MAX_IFS
#define DHD_MAX_IFS 16
#endif
#define MON_PRINT(format, ...) printk("DHD-MON: %s: " format, __func__, ##__VA_ARGS__)
#define MON_TRACE MON_PRINT

#define UPDATE_FREQ_MODULO  16

typedef struct monitor_interface {
	int radiotap_enabled;
    bool started;
    bool set_multicast;
    bool update_freq;
    int pkt_cnt;
    int freq;
	struct net_device* real_ndev;	/* The real interface that the monitor is on */
	struct net_device* mon_ndev;
} monitor_interface_t;

typedef struct dhd_linux_monitor {
	void *dhd_pub;
	monitor_states_t monitor_state;
	monitor_interface_t mon_if[DHD_MAX_IFS];
	struct mutex lock;		/* lock to protect mon_if */
	tsk_ctl_t	thr_sysioc_ctl;
} dhd_linux_monitor_t;

typedef struct dhd_monitor_header {
    struct ieee80211_radiotap_header radiotap_hdr;

    /* radiotap flags */
    u8 radiotap_flags;
    u8 padding_for_radiotap_flags;

    /* channel info */
    __le16 channel_mhz;
    __le16 channel_flags;

    /* RSSI in dBm */
    s8 rssi;
    s8 padding_for_rssi;
} __attribute__ ((packed)) dhd_monitor_header_t;

const struct ieee80211_radiotap_header RADIOTAP_HEADER_INITIALIZER = {
    PKTHDR_RADIOTAP_VERSION, /* it_version */
    0, /* it_pad */
    sizeof(dhd_monitor_header_t), /* it_len */
    (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_CHANNEL) | (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) /* it_present */
};

static dhd_linux_monitor_t g_monitor;

static struct net_device* lookup_real_netdev(char *name);
static monitor_interface_t* ndev_to_monif(struct net_device *ndev);
static int dhd_mon_if_open(struct net_device *ndev);
static int dhd_mon_if_stop(struct net_device *ndev);
static int dhd_mon_if_subif_start_xmit(struct sk_buff *skb, struct net_device *ndev);
static void dhd_mon_if_set_multicast_list(struct net_device *ndev);
static int dhd_mon_if_change_mac(struct net_device *ndev, void *addr);
static int _dhd_mon_sysioc_thread(void* data);
static void _dhd_mon_if_set_multicast_list(monitor_interface_t* mon_if);
static int get_freq(monitor_interface_t* mon_if);
static int set_tlv(uint32 tlv);

static const struct net_device_ops dhd_mon_if_ops = {
	.ndo_open		= dhd_mon_if_open,
	.ndo_stop		= dhd_mon_if_stop,
	.ndo_start_xmit		= dhd_mon_if_subif_start_xmit,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
	.ndo_set_rx_mode = dhd_mon_if_set_multicast_list,
#else
	.ndo_set_multicast_list = dhd_mon_if_set_multicast_list,
#endif
	.ndo_set_mac_address 	= dhd_mon_if_change_mac,
};

/**
 * Local static function defintions
 */

/* Look up dhd's net device table to find a match (e.g. interface "eth0" is a match for "mon.eth0"
 * "p2p-eth0-0" is a match for "mon.p2p-eth0-0")
 */
static struct net_device* lookup_real_netdev(char *name)
{
	struct net_device *ndev_found = NULL;

	int i;
	int len = 0;
	int last_name_len = 0;
	struct net_device *ndev;

	/* We need to find interface "p2p-p2p-0" corresponding to monitor interface "mon-p2p-0",
	 * Once mon iface name reaches IFNAMSIZ, it is reset to p2p0-0 and corresponding mon
	 * iface would be mon-p2p0-0.
	 */
	for (i = 0; i < DHD_MAX_IFS; i++) {
		ndev = dhd_idx2net(g_monitor.dhd_pub, i);

		/* Skip "p2p" and look for "-p2p0-x" in monitor interface name. If it
		 * it matches, then this netdev is the corresponding real_netdev.
		 */
		if (ndev && strstr(ndev->name, "p2p-p2p0")) {
			len = strlen("p2p");
		} else {
		/* if p2p- is not present, then the IFNAMSIZ have reached and name
		 * would have got reset. In this casse,look for p2p0-x in mon-p2p0-x
		 */
			len = 0;
		}
        MON_PRINT("ndev->name: %s, name: %s\n", ndev->name, name);
		if (ndev && strstr(name, (ndev->name + len))) {
			if (strlen(ndev->name) > last_name_len) {
				ndev_found = ndev;
				last_name_len = strlen(ndev->name);
			}
		}
	}

    MON_PRINT("ndev_found: %p\n", ndev_found);

	return ndev_found;
}

static monitor_interface_t* ndev_to_monif(struct net_device *ndev)
{
    int i;

    for (i = 0; i < DHD_MAX_IFS; i++) {
        if (g_monitor.mon_if[i].mon_ndev == ndev)
            return &g_monitor.mon_if[i];
    }

    return NULL;
}

static int dhd_mon_if_open(struct net_device *ndev)
{
    int ret = 0;

    MON_PRINT("enter\n");
    return ret;
}

static int dhd_mon_if_stop(struct net_device *ndev)
{
    int ret = 0;

    MON_PRINT("enter\n");
    return ret;
}

static int dhd_mon_if_subif_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
    int ret = 0;
    int rtap_len;
    int qos_len = 0;
    int dot11_hdr_len = 24;
    int snap_len = 6;
    unsigned char *pdata;
    unsigned short frame_ctl;
    unsigned char src_mac_addr[6];
    unsigned char dst_mac_addr[6];
    struct ieee80211_hdr *dot11_hdr;
    struct ieee80211_radiotap_header *rtap_hdr;
    monitor_interface_t* mon_if;

    MON_PRINT("enter\n");

    mon_if = ndev_to_monif(ndev);
    if (mon_if == NULL || mon_if->real_ndev == NULL) {
        MON_PRINT(" cannot find matched net dev, skip the packet\n");
        goto fail;
    }

    if (unlikely(skb->len < sizeof(struct ieee80211_radiotap_header)))
        goto fail;

    rtap_hdr = (struct ieee80211_radiotap_header *)skb->data;
    if (unlikely(rtap_hdr->it_version))
        goto fail;

    rtap_len = ieee80211_get_radiotap_len(skb->data);
    if (unlikely(skb->len < rtap_len))
        goto fail;

    MON_PRINT("radiotap len (should be 14): %d\n", rtap_len);

    /* Skip the ratio tap header */
    skb_pull(skb, rtap_len);

    dot11_hdr = (struct ieee80211_hdr *)skb->data;
    frame_ctl = le16_to_cpu(dot11_hdr->frame_control);
    /* Check if the QoS bit is set */
    if ((frame_ctl & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA) {
        /* Check if this ia a Wireless Distribution System (WDS) frame
         * which has 4 MAC addresses
         */
        if (dot11_hdr->frame_control & 0x0080)
            qos_len = 2;
        if ((dot11_hdr->frame_control & 0x0300) == 0x0300)
            dot11_hdr_len += 6;

        memcpy(dst_mac_addr, dot11_hdr->addr1, sizeof(dst_mac_addr));
        memcpy(src_mac_addr, dot11_hdr->addr2, sizeof(src_mac_addr));

        /* Skip the 802.11 header, QoS (if any) and SNAP, but leave spaces for
         * for two MAC addresses
         */
        skb_pull(skb, dot11_hdr_len + qos_len + snap_len - sizeof(src_mac_addr) * 2);
        pdata = (unsigned char*)skb->data;
        memcpy(pdata, dst_mac_addr, sizeof(dst_mac_addr));
        memcpy(pdata + sizeof(dst_mac_addr), src_mac_addr, sizeof(src_mac_addr));
        PKTSETPRIO(skb, 0);

        MON_PRINT("if name: %s, matched if name %s\n", ndev->name, mon_if->real_ndev->name);

        /* Use the real net device to transmit the packet */
        ret = dhd_start_xmit(skb, mon_if->real_ndev);

        return ret;
    }
fail:
    dev_kfree_skb(skb);
    return 0;
}

static int set_tlv(uint32 tlv)
{
    char iovbuf[12]; /* Room for "tlv" + '\0' + parameter */
    int ret;

    bcm_mkiovar("tlv", (char *)&tlv, sizeof(tlv), iovbuf, sizeof(iovbuf));
    ret = dhd_wl_ioctl_cmd(g_monitor.dhd_pub, WLC_SET_VAR, iovbuf, sizeof(iovbuf), TRUE, 0);
    if (unlikely(ret < 0)) {
        MON_PRINT("Failed to enable/disable bdcv2 tlv signaling: %s\n", bcmerrorstr(ret));
    }

    return ret;
}

static void _dhd_mon_if_set_multicast_list(monitor_interface_t* mon_if)
{
    int ifidx;
    int ret;
    uint32 tlv = -1;
    uint32 scansuppress = -1;
    uint32 mon;


    MON_TRACE("Enter.\n");

    ifidx = dhd_net2idx(g_monitor.dhd_pub, mon_if->real_ndev);

    mon = (mon_if->mon_ndev->flags & IFF_PROMISC) ? TRUE : FALSE;

    if (!mon_if->started && mon) {
        MON_PRINT("======= Monitor Mode Begin ===========\n");
        scansuppress = TRUE;
        netif_stop_queue(mon_if->real_ndev);
        tlv = WLFC_FLAGS_RSSI_SIGNALS;
    }
    else if (mon_if->started && !mon) {
        MON_PRINT("======= Monitor Mode End   ===========\n");
        scansuppress = htol32(FALSE);
        netif_wake_queue(mon_if->real_ndev);
        tlv = 0;
    }

    if (mon_if->started != mon) {
        mon = htol32(mon);
        ret = dhd_wl_ioctl_cmd(g_monitor.dhd_pub, WLC_SET_MONITOR, &mon, sizeof(mon), TRUE, ifidx);
        if (unlikely(ret < 0)) {
            MON_PRINT("Set monitor mode (%d) failed: %s\n", ltoh32(mon), bcmerrorstr(ret));
        }
    }
    mon_if->started = ltoh32(mon);

    if (scansuppress != -1) {
        scansuppress = htol32(scansuppress);
        ret = dhd_wl_ioctl_cmd(g_monitor.dhd_pub, WLC_SET_SCANSUPPRESS, &scansuppress, sizeof(scansuppress), TRUE, ifidx);
        if (unlikely(ret < 0)) {
            MON_PRINT("Set scansuppress (%d) failed: %s\n", ltoh32(scansuppress), bcmerrorstr(ret));
        }
    }

    if (tlv != -1) {
        set_tlv(tlv);
    }
}

static void dhd_mon_if_set_multicast_list(struct net_device *ndev)
{
    monitor_interface_t* mon_if;

    MON_TRACE("Enter.\n");

    mon_if = ndev_to_monif(ndev);
    if (mon_if == NULL || mon_if->real_ndev == NULL) {
        MON_PRINT(" cannot find matched net dev, skip the packet\n");
        return;
    }
    MON_PRINT("if name: %s, matched if name %s\n", ndev->name, mon_if->real_ndev->name);

    mon_if->set_multicast = TRUE;

    ASSERT(g_monitor.thr_sysioc_ctl.thr_pid >= 0);
    up(&(g_monitor.thr_sysioc_ctl.sema));
}

static int dhd_mon_if_change_mac(struct net_device *ndev, void *addr)
{
    int ret = 0;
    monitor_interface_t* mon_if;

    mon_if = ndev_to_monif(ndev);
    if (mon_if == NULL || mon_if->real_ndev == NULL) {
        MON_PRINT(" cannot find matched net dev, skip the packet\n");
    } else {
        MON_PRINT("enter, if name: %s, matched if name %s\n",
                ndev->name, mon_if->real_ndev->name);
    }
    return ret;
}

static int _dhd_mon_sysioc_thread(void* data)
{
    tsk_ctl_t *tsk = (tsk_ctl_t *)data;
    int i;
    monitor_interface_t* mon_if;

    MON_TRACE("Started.\n");

    while (down_interruptible(&tsk->sema) == 0) {
        SMP_RD_BARRIER_DEPENDS();
        if (tsk->terminated) {
            break;
        }

        for (i = 0; i < DHD_MAX_IFS; i++) {
            if (g_monitor.mon_if[i].mon_ndev == NULL) {
                continue;
            }
            mon_if = &(g_monitor.mon_if[i]);
            MON_PRINT("%s\n", mon_if->mon_ndev->name);

            if (mon_if->set_multicast) {
                _dhd_mon_if_set_multicast_list(mon_if);
                mon_if->set_multicast = FALSE;
            }
            if (mon_if->update_freq) {
                mon_if->freq = get_freq(mon_if);
                mon_if->update_freq = FALSE;
                MON_PRINT("Current freq: %d\n", mon_if->freq);
            }
        }

    }

    MON_TRACE("Stopped\n");
    complete_and_exit(&tsk->completed, 0);
}


static int get_freq(monitor_interface_t* mon_if)
{
    channel_info_t chan_info;
    enum ieee80211_band band;
    int ret, chan, freq, ifidx;

    ifidx = dhd_net2idx(g_monitor.dhd_pub, mon_if->real_ndev);
    ret = dhd_wl_ioctl_cmd(g_monitor.dhd_pub, WLC_GET_CHANNEL, &chan_info, sizeof(chan_info), FALSE, ifidx);

    if (unlikely(ret)) {
        MON_PRINT("Failed to get channel info.\n");
        return -1;
    }

    chan = ltoh32(chan_info.hw_channel);
    band = (chan <= CH_MAX_2G_CHANNEL) ? IEEE80211_BAND_2GHZ : IEEE80211_BAND_5GHZ;
    freq = ieee80211_channel_to_frequency(chan, band);

    MON_PRINT("chan = %d, band = %d, freq = %d\n", chan, band, freq);

    return freq;
}

/**
 * Global function definitions (declared in dhd_linux_mon.h)
 */

int dhd_add_monitor(char *name, struct net_device **new_ndev)
{
    int i;
    int idx = -1;
    int ret = 0;
    struct net_device* ndev = NULL;
    dhd_linux_monitor_t **dhd_mon;
    bool rtnl_locked = true;

    mutex_lock(&g_monitor.lock);

    MON_TRACE("enter, if name: %s\n", name);
    if (!name || !new_ndev) {
        MON_PRINT("invalid parameters\n");
        ret = -EINVAL;
        goto out;
    }

    /*
     * Find a vacancy
     */
    for (i = 0; i < DHD_MAX_IFS; i++)
        if (g_monitor.mon_if[i].mon_ndev == NULL) {
            idx = i;
            break;
        }
    if (idx == -1) {
        MON_PRINT("exceeds maximum interfaces\n");
        ret = -EFAULT;
        goto out;
    }
    MON_PRINT("Using mon index: %d\n", idx);

    ndev = alloc_etherdev(sizeof(dhd_linux_monitor_t*));
    if (!ndev) {
        MON_PRINT("failed to allocate memory\n");
        ret = -ENOMEM;
        goto out;
    }
    else {
        MON_PRINT("netdev allocated at: %p\n", ndev);
    }

    ndev->type = ARPHRD_IEEE80211_RADIOTAP;
    strncpy(ndev->name, name, IFNAMSIZ);
    ndev->name[IFNAMSIZ - 1] = 0;
    ndev->netdev_ops = &dhd_mon_if_ops;

    if (!rtnl_is_locked()) {
        rtnl_lock();
        rtnl_locked = false;
    }

    ret = register_netdevice(ndev);

    if (!rtnl_locked) {
        rtnl_unlock();
    }

    if (ret) {
        MON_PRINT(" register_netdevice failed (%d)\n", ret);
        goto out;
    }

    *new_ndev = ndev;
    memset(&(g_monitor.mon_if[idx]), 0, sizeof(g_monitor.mon_if[idx]));
    g_monitor.mon_if[idx].radiotap_enabled = TRUE;
    g_monitor.mon_if[idx].mon_ndev = ndev;
    g_monitor.mon_if[idx].real_ndev = lookup_real_netdev(name);
    g_monitor.mon_if[idx].started = FALSE;
    g_monitor.mon_if[idx].set_multicast = FALSE;
    g_monitor.mon_if[idx].update_freq = TRUE;
    g_monitor.mon_if[idx].freq = 2412;
    dhd_mon = (dhd_linux_monitor_t **)netdev_priv(ndev);
    *dhd_mon = &g_monitor;
    g_monitor.monitor_state = MONITOR_STATE_INTERFACE_ADDED;
    MON_PRINT("net device returned: 0x%p\n", ndev);
    MON_PRINT("found a matched net device, name %s\n", g_monitor.mon_if[idx].real_ndev->name);

out:
    if (ret && ndev)
        free_netdev(ndev);

    mutex_unlock(&g_monitor.lock);
    return ret;

}

int dhd_del_monitor(struct net_device *ndev)
{
    int i;
    bool rollback_lock = false;
    if (!ndev)
        return -EINVAL;
    mutex_lock(&g_monitor.lock);
    for (i = 0; i < DHD_MAX_IFS; i++) {
        if (g_monitor.mon_if[i].mon_ndev == ndev ||
                g_monitor.mon_if[i].real_ndev == ndev) {
            g_monitor.mon_if[i].real_ndev = NULL;
            if (rtnl_is_locked()) {
                rtnl_unlock();
                rollback_lock = true;
            }
            unregister_netdev(g_monitor.mon_if[i].mon_ndev);
            free_netdev(g_monitor.mon_if[i].mon_ndev);
            g_monitor.mon_if[i].mon_ndev = NULL;
            g_monitor.monitor_state = MONITOR_STATE_INTERFACE_DELETED;
            break;
        }
    }
    if (rollback_lock) {
        rtnl_lock();
        rollback_lock = false;
    }

    if (g_monitor.monitor_state !=
            MONITOR_STATE_INTERFACE_DELETED)
        MON_PRINT("interface not found in monitor IF array, is this a monitor IF? 0x%p\n",
                ndev);
    mutex_unlock(&g_monitor.lock);

    return 0;
}


int monitor_rx_frame(struct net_device* ndev, struct sk_buff* _skb, uint8 chan)
{

    monitor_interface_t* mon_if = NULL;
    int i, ifidx;
    struct sk_buff* skb;

    dhd_monitor_header_t hdr;

    (void) chan;

    for (i = 0; i < DHD_MAX_IFS; i++) {
        if (g_monitor.mon_if[i].real_ndev == ndev) {
            mon_if = &(g_monitor.mon_if[i]);
        }
    }
    if (mon_if == NULL) {
        return 0;
    }
    if (!(mon_if->mon_ndev->flags & IFF_PROMISC)) {
        return 0;
    }

    skb = skb_copy(_skb, GFP_KERNEL);
    if (unlikely(skb == NULL)) {
        MON_PRINT("Out of memory when copy skb.\n");
        return 0;
    }

    mon_if->pkt_cnt++;

    if (mon_if->pkt_cnt % UPDATE_FREQ_MODULO == 0) {
        mon_if->update_freq = TRUE;
        up(&(g_monitor.thr_sysioc_ctl.sema));
    }

    ifidx = dhd_net2idx(g_monitor.dhd_pub, mon_if->real_ndev);

    memset(&hdr, 0, sizeof(hdr));
    hdr.radiotap_hdr = RADIOTAP_HEADER_INITIALIZER;

    hdr.radiotap_flags = IEEE80211_RADIOTAP_F_FCS;

    hdr.channel_mhz = mon_if->freq;
    hdr.channel_flags = (hdr.channel_mhz < 5000? IEEE80211_CHAN_2GHZ: IEEE80211_CHAN_5GHZ);

#ifdef PROP_TXSTATUS
    hdr.rssi = *(s8*)(_skb->data-1) ;
#else /* PROP_TXSTATUS */
    hdr.rssi = 0;
#endif /* PROP_TXSTATUS */

    MON_PRINT("Packet RSSI = %d\n", hdr.rssi);

    skb_push(skb, sizeof(hdr));
    memcpy(skb->data, &hdr, sizeof(hdr));

    /* eth_type_trans will call skb_pull, so put this line at last. */
    skb->protocol = eth_type_trans(skb, mon_if->mon_ndev);

    netif_rx(skb);
    return 1;
}

int dhd_monitor_init(void *dhd_pub)
{
    struct net_device* first_ndev = NULL;
    struct net_device* mon_ndev = NULL;
    char mon_name[128];

    if (g_monitor.monitor_state == MONITOR_STATE_DEINIT) {
        g_monitor.dhd_pub = dhd_pub;
        mutex_init(&g_monitor.lock);
        g_monitor.monitor_state = MONITOR_STATE_INIT;

        PROC_START(_dhd_mon_sysioc_thread, &g_monitor, &g_monitor.thr_sysioc_ctl, 0, "dhd_mon_sysioc");

        first_ndev = dhd_idx2net(dhd_pub, 0);

        if (first_ndev != NULL) {
            sprintf(mon_name, "mon.%s", first_ndev->name);
            dhd_add_monitor(mon_name, &mon_ndev);
        }

    }
    MON_PRINT("dhd_pub: %p, monitor_state: %d\n", dhd_pub, g_monitor.monitor_state);

    return 0;
}

int dhd_monitor_uninit(void)
{
    int i;
    struct net_device *ndev;
    bool rollback_lock = false;
    mutex_lock(&g_monitor.lock);
    if (g_monitor.monitor_state != MONITOR_STATE_DEINIT) {
        for (i = 0; i < DHD_MAX_IFS; i++) {
            ndev = g_monitor.mon_if[i].mon_ndev;
            if (ndev) {
                if (rtnl_is_locked()) {
                    rtnl_unlock();
                    rollback_lock = true;
                }
                unregister_netdev(ndev);
                free_netdev(ndev);
                g_monitor.mon_if[i].real_ndev = NULL;
                g_monitor.mon_if[i].mon_ndev = NULL;
                if (rollback_lock) {
                    rtnl_lock();
                    rollback_lock = false;
                }
            }
        }
        g_monitor.monitor_state = MONITOR_STATE_DEINIT;
    }
    mutex_unlock(&g_monitor.lock);

    if (g_monitor.thr_sysioc_ctl.thr_pid >= 0) {
        PROC_STOP(&g_monitor.thr_sysioc_ctl);
    }

    return 0;
}
