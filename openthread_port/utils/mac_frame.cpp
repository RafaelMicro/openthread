/*
 *  Copyright (c) 2019, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "mac_frame.h"

#include <assert.h>
#include "mac/mac_frame.hpp"

using namespace ot;

//---------------------------------------------------------------------------------------------------------------------
// Helpers

static inline Error ParseAddrFields(const otRadioFrame *aFrame, Mac::Frame::ParseInfo &aFrameInfo)
{
    return aFrameInfo.ParseFrom(*static_cast<const Mac::Frame *>(aFrame), Mac::Frame::kParseAddrFields);
}

static inline Error ParseSecurityHeader(const otRadioFrame *aFrame, Mac::TxFrame::ParseInfo &aFrameInfo)
{
    return aFrameInfo.ParseFrom(*static_cast<const Mac::TxFrame *>(aFrame), Mac::Frame::kParseSecurityHeader);
}

static inline Error ParseFully(const otRadioFrame *aFrame, Mac::Frame::ParseInfo &aFrameInfo)
{
    return aFrameInfo.ParseFrom(*static_cast<const Mac::Frame *>(aFrame), Mac::Frame::kParseFully);
}

static bool IsFrameOfType(const otRadioFrame *aFrame, Mac::Frame::Type aType)
{
    bool                  matches = false;
    Mac::Frame::ParseInfo frameInfo;

    SuccessOrExit(ParseAddrFields(aFrame, frameInfo));
    matches = (frameInfo.mType == aType);

exit:
    return matches;
}

//---------------------------------------------------------------------------------------------------------------------

bool otMacFrameDoesAddrMatch(const otRadioFrame *aFrame,
                             otPanId             aPanId,
                             otShortAddress      aShortAddress,
                             const otExtAddress *aExtAddress)
{
    bool                  rval = true;
    Mac::Frame::ParseInfo frameInfo;

    if (ParseAddrFields(aFrame, frameInfo) != kErrorNone)
    {
        rval = false;
        ExitNow();
    }

    switch (frameInfo.mAddrs.mDestination.GetType())
    {
    case Mac::Address::kTypeShort:
        VerifyOrExit(frameInfo.mAddrs.mDestination.GetShort() == Mac::kShortAddrBroadcast ||
                         frameInfo.mAddrs.mDestination.GetShort() == aShortAddress,
                     rval = false);
        break;

    case Mac::Address::kTypeExtended:
        VerifyOrExit(frameInfo.mAddrs.mDestination.GetExtended() == *static_cast<const Mac::ExtAddress *>(aExtAddress),
                     rval = false);
        break;

    case Mac::Address::kTypeNone:
        break;
    }

    VerifyOrExit(frameInfo.mPanIds.IsDestinationPresent());
    VerifyOrExit(frameInfo.mPanIds.GetDestination() == Mac::kPanIdBroadcast ||
                     frameInfo.mPanIds.GetDestination() == aPanId,
                 rval = false);

exit:
    return rval;
}

bool otMacFrameIsAck(const otRadioFrame *aFrame)
{
    return IsFrameOfType(aFrame, Mac::Frame::kTypeAck);
}

bool otMacFrameIsData(const otRadioFrame *aFrame)
{
    return IsFrameOfType(aFrame, Mac::Frame::kTypeData);
}

bool otMacFrameIsCommand(const otRadioFrame *aFrame)
{
    return IsFrameOfType(aFrame, Mac::Frame::kTypeMacCmd);
}

bool otMacFrameIsDataRequest(const otRadioFrame *aFrame)
{
    bool                  matches = false;
    Mac::Frame::ParseInfo frameInfo;

    SuccessOrExit(ParseFully(aFrame, frameInfo));
    VerifyOrExit(frameInfo.mType == Mac::Frame::kTypeMacCmd);
    VerifyOrExit(frameInfo.mCommandId == Mac::Frame::kMacCmdDataRequest);
    matches = true;

exit:
    return matches;
}

bool otMacFrameIsAckRequested(const otRadioFrame *aFrame)
{
    Mac::Frame::ParseInfo frameInfo;

    IgnoreError(ParseAddrFields(aFrame, frameInfo));
    return frameInfo.mIsAckRequest;
}

static void GetOtMacAddress(const Mac::Address &aInAddress, otMacAddress *aOutAddress)
{
    switch (aInAddress.GetType())
    {
    case Mac::Address::kTypeNone:
        aOutAddress->mType = OT_MAC_ADDRESS_TYPE_NONE;
        break;

    case Mac::Address::kTypeShort:
        aOutAddress->mType                  = OT_MAC_ADDRESS_TYPE_SHORT;
        aOutAddress->mAddress.mShortAddress = aInAddress.GetShort();
        break;

    case Mac::Address::kTypeExtended:
        aOutAddress->mType                = OT_MAC_ADDRESS_TYPE_EXTENDED;
        aOutAddress->mAddress.mExtAddress = aInAddress.GetExtended();
        break;
    }
}

otError otMacFrameGetSrcAddr(const otRadioFrame *aFrame, otMacAddress *aMacAddress)
{
    Error                 error;
    Mac::Frame::ParseInfo frameInfo;

    SuccessOrExit(error = ParseAddrFields(aFrame, frameInfo));
    GetOtMacAddress(frameInfo.mAddrs.mSource, aMacAddress);

exit:
    return error;
}

otError otMacFrameGetDstAddr(const otRadioFrame *aFrame, otMacAddress *aMacAddress)
{
    Error                 error;
    Mac::Frame::ParseInfo frameInfo;

    SuccessOrExit(error = ParseAddrFields(aFrame, frameInfo));
    GetOtMacAddress(frameInfo.mAddrs.mDestination, aMacAddress);

exit:
    return error;
}

uint8_t otMacFrameGetSequence(const otRadioFrame *aFrame)
{
    Mac::Frame::ParseInfo frameInfo;

    IgnoreError(ParseAddrFields(aFrame, frameInfo));
    return frameInfo.mSequenceNum;
}

void otMacFrameProcessTransmitAesCcm(otRadioFrame *aFrame, const otExtAddress *aExtAddress)
{
    Mac::TxFrame::ParseInfo frameInfo;

    IgnoreError(ParseFully(aFrame, frameInfo));
    frameInfo.ProcessTransmitAesCcm(*static_cast<const Mac::ExtAddress *>(aExtAddress));
}

bool otMacFrameIsVersion2015(const otRadioFrame *aFrame)
{
    Mac::Frame::ParseInfo frameInfo;

    IgnoreError(ParseAddrFields(aFrame, frameInfo));
    return frameInfo.mVersion == Mac::Frame::kVersion2015;
}

void otMacFrameGenerateImmAck(const otRadioFrame *aFrame, bool aIsFramePending, otRadioFrame *aAckFrame)
{
    assert(aFrame != nullptr && aAckFrame != nullptr);

    static_cast<Mac::TxFrame *>(aAckFrame)->GenerateImmAck(*static_cast<const Mac::RxFrame *>(aFrame), aIsFramePending);
}

#if OPENTHREAD_CONFIG_THREAD_VERSION >= OT_THREAD_VERSION_1_2
otError otMacFrameGenerateEnhAck(const otRadioFrame *aFrame,
                                 bool                aIsFramePending,
                                 const uint8_t *     aIeData,
                                 uint8_t             aIeLength,
                                 otRadioFrame *      aAckFrame)
{
    assert(aFrame != nullptr && aAckFrame != nullptr);

    return static_cast<Mac::TxFrame *>(aAckFrame)->GenerateEnhAck(*static_cast<const Mac::RxFrame *>(aFrame),
                                                                  aIsFramePending, aIeData, aIeLength);
}
#endif

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
void otMacFrameSetCslIe(otRadioFrame *aFrame, uint16_t aCslPeriod, uint16_t aCslPhase)
{
    static_cast<Mac::Frame *>(aFrame)->UpdateCslIe(aCslPeriod, aCslPhase);
}
#endif // OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE

bool otMacFrameIsSecurityEnabled(otRadioFrame *aFrame)
{
    Mac::Frame::ParseInfo frameInfo;

    IgnoreError(ParseAddrFields(aFrame, frameInfo));
    return frameInfo.mIsSecurityEnabled;
}

bool otMacFrameIsKeyIdMode1(otRadioFrame *aFrame)
{
    bool                    matches = false;
    Mac::TxFrame::ParseInfo frameInfo;

    SuccessOrExit(ParseSecurityHeader(aFrame, frameInfo));
    matches = (frameInfo.mKeyIdMode == Mac::Frame::kKeyIdMode1);

exit:
    return matches;
}

uint8_t otMacFrameGetKeyId(otRadioFrame *aFrame)
{
    uint8_t                 keyIndex = 0;
    Mac::TxFrame::ParseInfo frameInfo;

    SuccessOrExit(ParseSecurityHeader(aFrame, frameInfo));
    keyIndex = frameInfo.mKeyIndex;

exit:
    return keyIndex;
}

void otMacFrameSetKeyId(otRadioFrame *aFrame, uint8_t aKeyId)
{
    Mac::TxFrame::ParseInfo frameInfo;

    IgnoreError(ParseSecurityHeader(aFrame, frameInfo));
    frameInfo.WriteKeyIndex(aKeyId);
}

uint32_t otMacFrameGetFrameCounter(otRadioFrame *aFrame)
{
    uint32_t                frameCounter = UINT32_MAX;
    Mac::TxFrame::ParseInfo frameInfo;

    SuccessOrExit(ParseSecurityHeader(aFrame, frameInfo));
    frameCounter = frameInfo.mFrameCounter;

exit:
    return frameCounter;
}

void otMacFrameSetFrameCounter(otRadioFrame *aFrame, uint32_t aFrameCounter)
{
    Mac::TxFrame::ParseInfo frameInfo;

    IgnoreError(ParseSecurityHeader(aFrame, frameInfo));
    frameInfo.WriteFrameCounter(aFrameCounter);
}

#if OPENTHREAD_CONFIG_MAC_CSL_RECEIVER_ENABLE
uint8_t otMacFrameGenerateCslIeTemplate(uint8_t *aDest)
{
    assert(aDest != nullptr);

    reinterpret_cast<Mac::CslIe *>(aDest)->Init();

    return sizeof(Mac::CslIe);
}
#endif

#if OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE
uint8_t otMacFrameGenerateEnhAckProbingIe(uint8_t *aDest, const uint8_t *aIeData, uint8_t aIeDataLength)
{
    Mac::LinkMetricsProbingIe *probingIe = reinterpret_cast<Mac::LinkMetricsProbingIe *>(aDest);

    assert(aDest != nullptr);

    probingIe->Init(aIeDataLength);

    if (aIeData != nullptr)
    {
        probingIe->WriteMetricsDataFrom(aIeData);
    }

    return probingIe->GetSize();
}

void otMacFrameSetEnhAckProbingIe(otRadioFrame *aFrame, const uint8_t *aData, uint8_t aDataLen)
{
    assert(aFrame != nullptr && aData != nullptr);

    reinterpret_cast<Mac::Frame *>(aFrame)->UpdateEnhAckProbingIe(aData, aDataLen);
}
#endif // OPENTHREAD_CONFIG_MLE_LINK_METRICS_SUBJECT_ENABLE
