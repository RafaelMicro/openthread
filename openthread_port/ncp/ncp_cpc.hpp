
#ifndef NCP_CPC_HPP_
#define NCP_CPC_HPP_

#include "openthread-core-config.h"
#ifdef CONFIG_OT_RCP_EZMESH
#include "cpc.h"
#include "cpc_api.h"
#include "ncp/ncp_base.hpp"

namespace ot {
namespace Ncp {

class NcpCPC : public NcpBase
{
    typedef NcpBase super_t;

public:
    /**
     * Constructor
     *
     * @param[in]  aInstance  The OpenThread instance structure.
     *
     */
    explicit NcpCPC(Instance *aInstance);

    /**
     * This method is called to transmit and receive data.
     *
     */
    void ProcessCpc(void);
    void HandleOpenEndpoint(void);

private:
    enum
    {
        kCpcTxBufferSize = 484
    };

    void HandleFrameAddedToNcpBuffer(void);

    static void HandleFrameAddedToNcpBuffer(void *                   aContext,
                                            Spinel::Buffer::FrameTag aTag,
                                            Spinel::Buffer::Priority aPriority,
                                            Spinel::Buffer *         aBuffer);

    void        SendToCPC(void);
    static void SendToCPC(Tasklet &aTasklet);
    static void HandleCPCSendDone(cpc_user_endpoint_id_t endpoint_id, void *buffer, void *arg, status_t status);
    void        HandleSendDone(void);
    static void HandleCPCReceive(cpc_user_endpoint_id_t endpoint_id, void *arg);
    static void HandleCPCEndpointError(uint8_t endpoint_id, void *arg);
    static void HandleEndpointError(Tasklet &aTasklet);
    void        HandleEndpointError(void);
    static void HandleOpenEndpoint(Tasklet &aTasklet);
    

    uint8_t                  mCpcTxBuffer[kCpcTxBufferSize];
    volatile bool                     mIsReady;
    volatile bool                     mIsWriting;
    cpc_endpoint_handle_t mUserEp;
    Tasklet                  mCpcSendTask;
    Tasklet                  mCpcEndpointErrorTask;
    Tasklet                  mCpcOpenEndpointTask;
};

} // namespace Ncp
} // namespace ot
#endif
#endif // NCP_CPC_HPP_
