#include "ncp_cpc.hpp"

#include <stdio.h>

#include <openthread/ncp.h>
#include <openthread/platform/logging.h>
#include <openthread/platform/misc.h>

#include "openthread-core-config.h"
#include "openthread-system.h" // for otSysEventSignalPending()
#include "common/code_utils.hpp"
#include "common/debug.hpp"
// #include "common/instance.hpp" // Stanley 2025/04/15
#include "common/encoding.hpp"  // Stanley 2025/04/15
#include "common/new.hpp"

#include "openthread_port.h"

#include "FreeRTOS.h"
#include "queue.h"
#include "semphr.h"
#include "task.h"

// #include "log.h"

#ifdef CONFIG_OT_RCP_EZMESH

namespace ot {
namespace Ncp {

extern "C" {
    extern void cpc_system_reset(cpc_system_reboot_mode_t reboot_mode);
}

#if OPENTHREAD_ENABLE_NCP_VENDOR_HOOK == 0

static SemaphoreHandle_t xSemaphore = NULL;
static StaticSemaphore_t xSemaphoreBuffer;

static OT_DEFINE_ALIGNED_VAR(sNcpRaw, sizeof(NcpCPC), uint64_t);

extern "C" void otAppNcpInit(otInstance *aInstance)
{
    NcpCPC *  ncpCPC   = nullptr;
    Instance *instance = static_cast<Instance *>(aInstance);

    ncpCPC = new (&sNcpRaw) NcpCPC(instance);

    if (ncpCPC == nullptr || ncpCPC != NcpBase::GetNcpInstance())
    {
        OT_ASSERT(false);
    }

    xSemaphore = xSemaphoreCreateBinaryStatic(&xSemaphoreBuffer);
    xSemaphoreGive(xSemaphore);    
}

#endif // OPENTHREAD_ENABLE_NCP_VENDOR_HOOK == 0

NcpCPC::NcpCPC(Instance *aInstance)
    : NcpBase(aInstance)
    , mIsReady(false)
    , mIsWriting(false)
    , mCpcSendTask(*aInstance, SendToCPC)
    , mCpcEndpointErrorTask(*aInstance, HandleEndpointError)
    , mCpcOpenEndpointTask(*aInstance, HandleOpenEndpoint)
{
}

void NcpCPC::HandleOpenEndpoint(Tasklet &aTasklet)
{
    OT_UNUSED_VARIABLE(aTasklet);
    static_cast<NcpCPC *>(GetNcpInstance())->HandleOpenEndpoint();
}

void NcpCPC::HandleOpenEndpoint(void)
{

    status_t status = cpc_open_service_endpoint(&mUserEp, CPC_ENDPOINT_15_4, 0, 1);

    if (status == CPC_STATUS_ALREADY_EXISTS)
    {
        return;
    }
    else if (status == CPC_STATUS_BUSY)
    {
        static_cast<NcpCPC *>(GetNcpInstance())->mCpcOpenEndpointTask.Post();
        return;
    }    

    OT_ASSERT(status == CPC_STATUS_OK);

     status = cpc_set_endpoint_option(&mUserEp, CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED,
                                        reinterpret_cast<void *>(HandleCPCSendDone));

    OT_ASSERT(status == CPC_STATUS_OK);

    status = cpc_set_endpoint_option(&mUserEp, CPC_ENDPOINT_ON_IFRAME_RECEIVE,
                                        reinterpret_cast<void *>(HandleCPCReceive));

    OT_ASSERT(status == CPC_STATUS_OK);

    status = cpc_set_endpoint_option(&mUserEp, CPC_ENDPOINT_ON_ERROR,
                                        reinterpret_cast<void *>(HandleCPCEndpointError));

    OT_ASSERT(status == CPC_STATUS_OK);

    mTxFrameBuffer.SetFrameAddedCallback(HandleFrameAddedToNcpBuffer, this);
}

void NcpCPC::HandleFrameAddedToNcpBuffer(void *                   aContext,
                                         Spinel::Buffer::FrameTag aTag,
                                         Spinel::Buffer::Priority aPriority,
                                         Spinel::Buffer *         aBuffer)
{
    OT_UNUSED_VARIABLE(aBuffer);
    OT_UNUSED_VARIABLE(aTag);
    OT_UNUSED_VARIABLE(aPriority);

    static_cast<NcpCPC *>(aContext)->HandleFrameAddedToNcpBuffer();
}

void NcpCPC::HandleFrameAddedToNcpBuffer(void)
{
    // log_info("mIsReady %d mIsWriting %d", mIsReady, mIsWriting);
    if (mIsReady && !mIsWriting)
        mCpcSendTask.Post();
}

void NcpCPC::SendToCPC(Tasklet &aTasklet)
{
    OT_UNUSED_VARIABLE(aTasklet);
    static_cast<NcpCPC *>(GetNcpInstance())->SendToCPC();
}

// may need to be updated to handle sleepy devices. Refer to NcpUart::EncodeAndSendToUart
void NcpCPC::SendToCPC(void)
{
    Spinel::Buffer &txFrameBuffer = mTxFrameBuffer;
    uint16_t        bufferLen;
    uint16_t        offset = 0;
    status_t        status;

    VerifyOrExit(mIsReady && !mIsWriting && !txFrameBuffer.IsEmpty());

    mIsWriting = true;
    // log_info("send");

    // Concatenate multiple spinel buffers for efficiency over CPC.
    while (!txFrameBuffer.IsEmpty())
    {
        IgnoreError(txFrameBuffer.OutFrameBegin());
        bufferLen = txFrameBuffer.OutFrameGetLength();
        if (offset + sizeof(uint16_t) + bufferLen < kCpcTxBufferSize) {
            BigEndian::WriteUint16(bufferLen, mCpcTxBuffer + offset);
            offset += sizeof(uint16_t);
            txFrameBuffer.OutFrameRead(bufferLen, mCpcTxBuffer + offset);
            offset += bufferLen;
            IgnoreError(txFrameBuffer.OutFrameRemove());
        }
        else
        {
          break;
        }
    }

    if (cpc_write(&mUserEp, mCpcTxBuffer, offset, 0, NULL) != STATUS_OK)
    {
        mIsWriting = false;
    }
    xSemaphoreTake(xSemaphore, portMAX_DELAY);

exit:
    // If the CPCd link isn't ready yet, just remove the frame from
    // the queue so that it doesn't fill up unnecessarily
    if (!mIsReady)
    {
        IgnoreError(txFrameBuffer.OutFrameRemove());
    }

    return;
}

void NcpCPC::HandleCPCSendDone(cpc_user_endpoint_id_t endpoint_id, void *buffer, void *arg, status_t status)
{
    OT_UNUSED_VARIABLE(endpoint_id);
    OT_UNUSED_VARIABLE(buffer);
    OT_UNUSED_VARIABLE(arg);
    OT_UNUSED_VARIABLE(status);
    static_cast<NcpCPC *>(GetNcpInstance())->HandleSendDone();
}

void NcpCPC::HandleSendDone(void)
{
    mIsWriting = false;
    memset(mCpcTxBuffer, 0, sizeof(mCpcTxBuffer));
    // log_info("send d");
    // log_info("mIsReady %d mIsWriting %d tx buff %d", mIsReady, mIsWriting, mTxFrameBuffer.IsEmpty());
    xSemaphoreGive(xSemaphore);
    if (!mTxFrameBuffer.IsEmpty())
        mCpcSendTask.Post();
}

void NcpCPC::HandleCPCReceive(cpc_user_endpoint_id_t endpoint_id, void *arg)
{
    OT_UNUSED_VARIABLE(endpoint_id);
    OT_UNUSED_VARIABLE(arg);
    otSysEventSignalPending(); // wakeup ot task
}

void NcpCPC::HandleCPCEndpointError(uint8_t endpoint_id, void *arg)
{
    OT_UNUSED_VARIABLE(endpoint_id);
    OT_UNUSED_VARIABLE(arg);

    // Can't close and open endpoints in this context
    static_cast<NcpCPC *>(GetNcpInstance())->mCpcEndpointErrorTask.Post();
}

void NcpCPC::HandleEndpointError(Tasklet &aTasklet)
{
    OT_UNUSED_VARIABLE(aTasklet);
    static_cast<NcpCPC *>(GetNcpInstance())->HandleEndpointError();
}

void NcpCPC::HandleEndpointError(void)
{
    uint8_t ep_state;
    ep_state = cpc_get_endpoint_state(&mUserEp);

    log_warn("EP 15.4 Error %d!", ep_state);
    if(ep_state == CPC_STATE_ERROR_FAULT)
        cpc_system_reset(1);

    cpc_set_state(&mUserEp, CPC_STATE_OPEN);

    vPortEnterCritical();
    mUserEp.ref_count = 1;
    vPortExitCritical();
}

extern "C" void rf_ot_cpc_rcp_process(void)
{
    NcpCPC *ncpCPC = static_cast<NcpCPC *>(NcpBase::GetNcpInstance());

    if (ncpCPC != nullptr)
    {
        ncpCPC->ProcessCpc();
    }
}
extern "C" void rf_ot_cpc_init(void)
{
    NcpCPC *ncpCPC = static_cast<NcpCPC *>(NcpBase::GetNcpInstance());

    if (ncpCPC != nullptr)
    {
        ncpCPC->HandleOpenEndpoint();
    }
}
void NcpCPC::ProcessCpc(void)
{
    status_t status;
    void *      data;
    uint16_t    dataLength;
    // HandleOpenEndpoint();

    status = cpc_read(&mUserEp, &data, &dataLength, 0,
                         CPC_FLAG_NO_BLOCK); // In bare-metal read is always
                                                // non-blocking, but with rtos
                                                // since this function is called
                                                // in the cpc task, it must not
                                                // block.
    SuccessOrExit(status);

    if (!mIsReady)
    {
        mIsReady = true;
    }
    super_t::HandleReceive(static_cast<uint8_t *>(data), dataLength);
    // log_info_hexdump("NCP RX", (uint8_t *)data, dataLength);
    status = cpc_free_rx_buffer(data);
    OT_ASSERT(status == CPC_STATUS_OK);
exit:
    if (mIsReady && !mTxFrameBuffer.IsEmpty() && !mIsWriting)
        mCpcSendTask.Post();
}

} // namespace Ncp
} // namespace ot

#endif // OPENTHREAD_CONFIG_NCP_CPC_ENABLE
