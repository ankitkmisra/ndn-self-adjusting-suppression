/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2025 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 *
 * ndn-svs library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, in version 2.1 of the License.
 *
 * ndn-svs library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 */

#include "core.hpp"
#include "tlv.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include <chrono>
#include <iostream>
#include <sstream>

#ifdef NDN_SVS_COMPRESSION
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filter/lzma.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#endif

namespace ndn::svs {

SVSyncCore::SVSyncCore(ndn::Face& face,
                       const Name& syncPrefix,
                       const UpdateCallback& onUpdate,
                       const SecurityOptions& securityOptions,
                       const NodeID& nid,
                       int timerSetting,
                       int timerScaling)
  : m_face(face)
  , m_syncPrefix(syncPrefix)
  , m_securityOptions(securityOptions)
  , m_id(nid)
  , m_onUpdate(onUpdate)
  , m_suppressionDict()
  , m_maxSuppressionTime(200_ms)
  , m_periodicSyncTime(30_s)
  , m_periodicSyncJitter(0.1)
  , m_rng(ndn::random::getRandomNumberEngine())
  , m_retxDist(m_periodicSyncTime.count() * (1.0 - m_periodicSyncJitter),
               m_periodicSyncTime.count() * (1.0 + m_periodicSyncJitter))
  , m_intrReplyDist(0, m_maxSuppressionTime.count())
  , m_keyChainMem("pib-memory:", "tpm-memory:")
  , m_scheduler(m_face.getIoContext())
  , m_timerSetting(timerSetting) // Initialize timer setting
  , m_propagationDelays() // Initialize the propagation delays dictionary
  , m_timerScaling(timerScaling)
{
  // Register sync interest filter
  m_syncRegisteredPrefix =
    m_face.setInterestFilter(syncPrefix,
                             std::bind(&SVSyncCore::onSyncInterest, this, _2),
                             std::bind(&SVSyncCore::sendInitialInterest, this),
                             [](auto&&...) { NDN_THROW(Error("Failed to register sync prefix")); });
}

static inline int
suppressionCurve(int constFactor, int value)
{
  // This curve increases the probability that only one or a few
  // nodes pick lower values for timers compared to other nodes.
  // This leads to better suppression results.
  // Increasing the curve factor makes the curve steeper =>
  // better for more nodes, but worse for fewer nodes.

  float c = constFactor;
  float v = value;
  float f = 10.0; // curve factor

  return static_cast<int>(c * (1.0 - std::exp((v - c) / (c / f))));
}

void
SVSyncCore::updateMaxSuppressionTime()
{
  if (m_timerSetting == 0) {
    // If timer_setting is 0, use the fixed suppression time (200 ms)
    // This should not be required, but just a sanity check
  }
  else {
    std::lock_guard<std::mutex> lock(m_propagationDelaysMutex);

    if (!m_propagationDelays.empty()) {
      
      // Calculate the average propagation delay across all nodes and their last 5 delays
      uint64_t totalDelay = 0;
      size_t totalCount = 0;

      for (const auto& [nodeId, delays] : m_propagationDelays) {
        for (uint64_t delay : delays) {
          totalDelay += delay;
          totalCount++;
        }
      }

      if (totalCount == 0) {
        // If no delays are recorded, use the default value
        m_maxSuppressionTime = 200_ms;
        return;
      }

      uint64_t averageDelay = totalDelay / totalCount;

      // Update m_maxSuppressionTime to the average delay
      m_maxSuppressionTime = ndn::time::milliseconds(averageDelay * m_timerScaling);

      // Update the distributions
      m_intrReplyDist = std::uniform_int_distribution<>(0, m_maxSuppressionTime.count());

    }
  }

  std::cout << "Max suppression time updated to: " << m_maxSuppressionTime.count() << std::endl;
}

void
SVSyncCore::sendInitialInterest()
{
  // Wait for 100ms before sending the first sync interest
  // This is necessary to give other things time to initialize
  m_scheduler.schedule(100_ms, [this] {
    m_initialized = true;
    retxSyncInterest(true, 0);
  });
}

void
SVSyncCore::onSyncInterest(const Interest& interest)
{
  switch (m_securityOptions.interestSigner->signingInfo.getSignerType()) {
    case security::SigningInfo::SIGNER_TYPE_NULL:
      onSyncInterestValidated(interest);
      return;

    case security::SigningInfo::SIGNER_TYPE_HMAC:
      if (security::verifySignature(interest,
                                    m_keyChainMem.getTpm(),
                                    m_securityOptions.interestSigner->signingInfo.getSignerName(),
                                    DigestAlgorithm::SHA256))
        onSyncInterestValidated(interest);
      return;

    default:
      if (m_securityOptions.validator)
        m_securityOptions.validator->validate(
          interest, std::bind(&SVSyncCore::onSyncInterestValidated, this, _1), nullptr);
      else
        onSyncInterestValidated(interest);
      return;
  }
}

void
SVSyncCore::onSyncInterestValidated(const Interest& interest)
{
  // Get incoming face (this is needed by NLSR)
  uint64_t incomingFace = 0;
  {
    auto tag = interest.getTag<ndn::lp::IncomingFaceIdTag>();
    if (tag) {
      incomingFace = tag->get();
    }
  }

  // Check for invalid Interest
  if (!interest.hasApplicationParameters()) {
    return;
  }

  // Decode state parameters
  ndn::Block params = interest.getApplicationParameters();
  params.parse();

#ifdef NDN_SVS_COMPRESSION
  // Decompress if necessary. The spec requires that if an LZMA block is
  // present, then no other blocks are present (everything is compressed
  // together)
  if (params.find(tlv::LzmaBlock) != params.elements_end()) {
    auto lzmaBlock = params.get(tlv::LzmaBlock);

    boost::iostreams::filtering_istreambuf in;
    in.push(boost::iostreams::lzma_decompressor());
    in.push(boost::iostreams::array_source(reinterpret_cast<const char*>(lzmaBlock.value()),
                                           lzmaBlock.value_size()));
    ndn::OBufferStream decompressed;
    boost::iostreams::copy(in, decompressed);

    auto parsed = ndn::Block::fromBuffer(decompressed.buf());
    if (!std::get<0>(parsed)) {
      // TODO: log error parsing inner block
      return;
    }

    params = std::get<1>(parsed);
    params.parse();
  }
#endif

  // Parse sender node ID and timestamp at which it was sent, if timer setting is not 0
  std::string senderNodeId = "";
  uint64_t timestamp = 0, time_diff = 0;
  bool isSuppressionTriggered = false;
  std::unordered_map<std::string, uint64_t> recv_suppressionDict;
  if (m_timerSetting != 0) {
    try {
      senderNodeId = ndn::encoding::readString(params.get(tlv::SenderNodeId));

      timestamp = ndn::encoding::readNonNegativeInteger(params.get(tlv::Timestamp));
      auto now = std::chrono::system_clock::now();
      auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
      auto epoch = now_ms.time_since_epoch();
      auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
      time_diff = current_time - timestamp;

      if (m_timerSetting == 2) {
        isSuppressionTriggered = (ndn::encoding::readNonNegativeInteger(params.get(tlv::SuppressionFlag)) == 1);
        // if (isSuppressionTriggered)
        //   std::cout << "Received suppression interest from " << senderNodeId << std::endl;

        std::string recv_str_suppressionDict = ndn::encoding::readString(params.get(tlv::SuppressionDict));
        std::istringstream iss(recv_str_suppressionDict);
        std::string entry;
        while (getline(iss, entry, ',')) {
          size_t pos = entry.find(':');
          if (pos != std::string::npos) {
              std::string key = entry.substr(0, pos);
              uint64_t value = stoull(entry.substr(pos + 1));
              recv_suppressionDict[key] = value;
              // std::cout << "Key: " << key << ", Value: " << value << std::endl;
          }
        }
      }
    } catch (ndn::tlv::Error& e) {
      std::cerr << "Error parsing something: " << e.what() << std::endl;
      return;
    }
  }
  
  // Get state vector
  std::shared_ptr<VersionVector> vvOther;
  try {
    vvOther = std::make_shared<VersionVector>(params.get(tlv::StateVector));
  } catch (ndn::tlv::Error&) {
    // TODO: log error
    return;
  }

  // Read extra mapping blocks
  if (m_recvExtraBlock) {
    try {
      m_recvExtraBlock(params.get(tlv::MappingData), *vvOther);
    } catch (std::exception&) {
      // TODO: log error but continue
    }
  }

  if (m_timerSetting == 1) {
    if (senderNodeId != m_id.toUri()) {
        // Update the propagation delays queue for the sender node ID
        {
          std::lock_guard<std::mutex> lock(m_propagationDelaysMutex);
          auto& delays = m_propagationDelays[senderNodeId];
          delays.push_back(std::min((int)(time_diff), 200));

          // Keep only the last 5 delays
          if (delays.size() > 5) {
            delays.pop_front();
          }
        }

        // Update m_maxSuppressionTime based on the average propagation delay
        updateMaxSuppressionTime();
    }
  }

  if (m_timerSetting == 2 && isSuppressionTriggered) {
    if (senderNodeId != m_id.toUri()) {
      auto it = recv_suppressionDict.find(m_id.toUri());
      if (it != recv_suppressionDict.end()) {
        auto recv_time_diff = it->second;

        // std::cout << std::endl;
        // std::cout << senderNodeId << std::endl;
        // std::cout << time_diff << std::endl;
        // std::cout << recv_time_diff << std::endl;
  
        {
          std::lock_guard<std::mutex> lock(m_propagationDelaysMutex);
          auto& delays = m_propagationDelays[senderNodeId];
          delays.push_back(std::min((int)((time_diff + recv_time_diff) / 2), 200));

          // Keep only the last 1 delays
          if (delays.size() > 3) {
            delays.pop_front();
          }
        }
        updateMaxSuppressionTime();
      }
    }
  }

  // Merge state vector
  auto result = mergeStateVector(*vvOther);

  // Callback if missing data found
  if (!result.missingInfo.empty()) {
    for (auto& e : result.missingInfo)
      e.incomingFace = incomingFace;
    m_onUpdate(result.missingInfo);
  }

  // Try to record; the call will check if in suppression state
  if (recordVector(*vvOther, senderNodeId, time_diff))
    return;

  // If incoming state identical/newer to local vector, reset timer
  // If incoming state is older, send sync interest immediately
  if (!result.myVectorNew) {
    retxSyncInterest(false, 0);
  } else {
    enterSuppressionState(*vvOther, senderNodeId, time_diff);
    // Check how much time is left on the timer,
    // reset to ~m_intrReplyDist if more than that.
    int delay = m_intrReplyDist(m_rng);

    // Curve the delay for better suppression in large groups
    // TODO: efficient curve depends on number of active nodes
    delay = suppressionCurve(m_maxSuppressionTime.count(), delay);

    if (getCurrentTime() + delay * 1000 < m_nextSyncInterest) {
      retxSyncInterest(false, delay);
    }
  }
}

void
SVSyncCore::retxSyncInterest(bool send, unsigned int delay)
{
  if (send) {
    std::lock_guard<std::mutex> lock(m_recordedVvMutex);

    // Only send interest if in steady state or local vector has newer state
    // than recorded interests
    if (!m_recordedVv)
      sendSyncInterest();
    else if (mergeStateVector(*m_recordedVv).myVectorNew) {
      // std::cout << "Sending suppression interest" << std::endl;
      sendSyncInterest(true);
    }
      
      
    m_recordedVv = nullptr;
    if (m_timerSetting == 2) {
      std::lock_guard<std::mutex> lock(m_suppressionDictMutex);
      m_suppressionDict.clear();
    }
  }

  if (delay == 0)
    delay = m_retxDist(m_rng);

  {
    std::lock_guard<std::mutex> lock(m_schedulerMutex);

    // Store the scheduled time
    m_nextSyncInterest = getCurrentTime() + 1000 * delay;

    m_retxEvent = m_scheduler.schedule(time::milliseconds(delay), [this] { retxSyncInterest(true, 0); });
  }
}

void
SVSyncCore::sendSyncInterest(bool isSuppressionTriggered)
{
  if (!m_initialized)
    return;

  // Build app parameters
  ndn::encoding::EncodingBuffer enc;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    size_t length = 0;

    // Add extra mapping blocks
    if (m_getExtraBlock)
      length += ndn::encoding::prependBlock(enc, m_getExtraBlock(m_vv));

    // Add state vector
    length += ndn::encoding::prependBlock(enc, m_vv.encode());

    if (m_timerSetting != 0) {
      // Add sender node ID as a binary block
      length += ndn::encoding::prependStringBlock(enc, tlv::SenderNodeId, m_id.toUri());

      // Add timestamp
      auto now = std::chrono::system_clock::now();
      auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
      auto epoch = now_ms.time_since_epoch();
      auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
      length += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::Timestamp, value);

      if (m_timerSetting == 2) {
        // Add suppression flag
        uint64_t int_isSuppressionTriggered = isSuppressionTriggered ? 1 : 0;
        length += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::SuppressionFlag, int_isSuppressionTriggered);

        // Add string representation of list of suppressed nodes (with timestamps of suppression dict addition)
        std::lock_guard<std::mutex> lock(m_suppressionDictMutex);
        std::ostringstream str_suppressionDict;
        bool first = true;
        for (const auto& [key, value] : m_suppressionDict) {
            if (!first)
                str_suppressionDict << ","; // Separate entries
            str_suppressionDict << key << ":" << value;
            // std::cout << "Key: " << key << ", Value: " << value << std::endl;
            
            first = false;
        }
        length += ndn::encoding::prependStringBlock(enc, tlv::SuppressionDict, str_suppressionDict.str());
      }
    }

    // Add length and ApplicationParameters type
    enc.prependVarNumber(length);
    enc.prependVarNumber(ndn::tlv::ApplicationParameters);
  }

  ndn::Block wire = enc.block();
  wire.encode();

#ifdef NDN_SVS_COMPRESSION
  boost::iostreams::filtering_istreambuf in;
  in.push(boost::iostreams::lzma_compressor());
  in.push(boost::iostreams::array_source(reinterpret_cast<const char*>(wire.data()), wire.size()));
  ndn::OBufferStream compressed;
  boost::iostreams::copy(in, compressed);
  wire = ndn::Block(tlv::LzmaBlock, compressed.buf());
  wire.encode();
#endif

  // Create Sync Interest
  Interest interest(Name(m_syncPrefix).appendVersion(2));
  interest.setApplicationParameters(wire);
  interest.setInterestLifetime(1_ms);

  switch (m_securityOptions.interestSigner->signingInfo.getSignerType()) {
    case security::SigningInfo::SIGNER_TYPE_NULL:
      break;

    case security::SigningInfo::SIGNER_TYPE_HMAC:
      m_keyChainMem.sign(interest, m_securityOptions.interestSigner->signingInfo);
      break;

    default:
      m_securityOptions.interestSigner->sign(interest);
      break;
  }

  std::cout << "Sending Sync interest" << std::endl;

  m_face.expressInterest(interest, nullptr, nullptr, nullptr);
}

SVSyncCore::MergeResult
SVSyncCore::mergeStateVector(const VersionVector& vvOther)
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  SVSyncCore::MergeResult result;

  // Check if other vector has newer state
  for (const auto& entry : vvOther) {
    NodeID nidOther = entry.first;
    SeqNo seqOther = entry.second;
    SeqNo seqCurrent = m_vv.get(nidOther);

    if (seqCurrent < seqOther) {
      result.otherVectorNew = true;

      SeqNo startSeq = m_vv.get(nidOther) + 1;
      result.missingInfo.push_back({ nidOther, startSeq, seqOther, 0 });

      m_vv.set(nidOther, seqOther);
    }
  }

  // Check if I have newer state
  for (const auto& entry : m_vv) {
    NodeID nid = entry.first;
    SeqNo seq = entry.second;
    SeqNo seqOther = vvOther.get(nid);

    // Ignore this node if it was last updated within network RTT
    if (time::system_clock::now() - m_vv.getLastUpdate(nid) < m_maxSuppressionTime)
      continue;

    // std::cout << "Inside mergeStateVector, comparing node: " << nid
    //       << ", local seq: " << seq
    //       << ", recorded seq: " << seqOther << ", verdict: " << (seqOther < seq) << std::endl;

    if (seqOther < seq) {
      result.myVectorNew = true;
      break;
    }
  }

  return result;
}

void
SVSyncCore::reset(bool isOnInterest)
{
}

SeqNo
SVSyncCore::getSeqNo(const NodeID& nid) const
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;
  return m_vv.get(t_nid);
}

void
SVSyncCore::updateSeqNo(const SeqNo& seq, const NodeID& nid)
{
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;

  SeqNo prev;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    prev = m_vv.get(t_nid);
    m_vv.set(t_nid, seq);
  }

  if (seq > prev)
    retxSyncInterest(false, 1);
}

std::set<NodeID>
SVSyncCore::getNodeIds() const
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  std::set<NodeID> sessionNames;
  for (const auto& nid : m_vv) {
    sessionNames.insert(nid.first);
  }
  return sessionNames;
}

long
SVSyncCore::getCurrentTime() const
{
  return std::chrono::duration_cast<std::chrono::microseconds>(
           std::chrono::steady_clock::now().time_since_epoch())
    .count();
}

bool
SVSyncCore::recordVector(const VersionVector& vvOther, std::string senderNodeId, uint64_t time_diff)
{
  std::lock_guard<std::mutex> lock(m_recordedVvMutex);

  if (!m_recordedVv)
    return false;

  std::lock_guard<std::mutex> lock1(m_vvMutex);

  for (const auto& entry : vvOther) {
    NodeID nidOther = entry.first;
    SeqNo seqOther = entry.second;
    SeqNo seqCurrent = m_recordedVv->get(nidOther);

    if (seqCurrent < seqOther) {
      m_recordedVv->set(nidOther, seqOther);
    }
  }

  if (m_timerSetting == 2) {
    std::lock_guard<std::mutex> lock(m_suppressionDictMutex);
    if (senderNodeId == "" || time_diff == 0)
      std::cerr << "Error!" << std::endl;
    m_suppressionDict[senderNodeId] = time_diff;
  }

  return true;
}

void
SVSyncCore::enterSuppressionState(const VersionVector& vvOther, std::string senderNodeId, uint64_t time_diff)
{
  std::lock_guard<std::mutex> lock(m_recordedVvMutex);

  if (!m_recordedVv)
    m_recordedVv = std::make_unique<VersionVector>(vvOther);

  if (m_timerSetting == 2) {
    std::lock_guard<std::mutex> lock(m_suppressionDictMutex);
    if (senderNodeId == "" || time_diff == 0 || !m_suppressionDict.empty())
      std::cerr << "Error!" << std::endl;
    m_suppressionDict[senderNodeId] = time_diff;
  }
}

} // namespace ndn::svs
