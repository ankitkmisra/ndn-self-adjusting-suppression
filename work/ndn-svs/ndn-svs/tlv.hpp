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

#ifndef NDN_SVS_TLV_HPP
#define NDN_SVS_TLV_HPP

#include <cstdint>

namespace ndn::svs::tlv {

enum : uint32_t
{
  StateVector = 201,
  StateVectorEntry = 202,
  SeqNo = 204,
  MappingData = 205,
  MappingEntry = 206,
  LzmaBlock = 211,
  Timestamp = 212,
  SenderNodeId = 213,
  SuppressionFlag = 214,
  SuppressionDict = 215
};

} // namespace ndn::svs::tlv

#endif // NDN_SVS_TLV_HPP
