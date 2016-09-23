
#ifndef _NEUFBOX_QOS_H_
#define _NEUFBOX_QOS_H_

#define DSCP_DOWN_MASK	(0x38)				/* 111.000 */
#define DSCP_VOIP_UP	(VOIP_DSCP)			/* 101.101 */
#define DSCP_VOIP_DOWN	(VOIP_DSCP & DSCP_DOWN_MASK)	/* 101.000 */
#define DSCP_VIDEO_UP	(TV_DSCP)			/* 100.100 */
#define DSCP_VIDEO_DOWN (DSCP_VIDEO_UP & DSCP_DOWN_MASK)/* 100.000 */

static inline int neufbox_qos(struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		int dscp = (skb->nh.iph->tos >> 2);

		return !((dscp == DSCP_VOIP_DOWN)
			 || (dscp == DSCP_VOIP_UP)
			 || (dscp == DSCP_VIDEO_DOWN)
			 || (dscp == DSCP_VIDEO_UP));
	}

	return 1;
}

#define GET_SKBUFF_QOS(skb) neufbox_qos(skb)

#endif				/* _NEUFBOX_QOS_H_ */
