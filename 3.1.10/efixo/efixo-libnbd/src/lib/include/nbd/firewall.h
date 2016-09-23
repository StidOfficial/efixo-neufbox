/*
 * File:   firewall.h
 * Author: vbx
 *
 * Created on 19 juillet 2010, 11:43
 */

#ifndef LIBNBD_FIREWALL_H
#define LIBNBD_FIREWALL_H

extern int nbd_firewall_add(const char *rulename, const char *proto,
			    const char *direction, const char *dstip,
			    const char *dstport, const char *srcip,
			    const char *srcport, const char *policy);
extern int nbd_firewall_del_by_index(unsigned int idx);

#endif /* _PLUGIN_FIREWALL_H_ */
