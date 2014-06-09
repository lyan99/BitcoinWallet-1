/**
 * Copyright 2014 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.BitcoinWallet;

import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageListener;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.Sha256Hash;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Handle inventory requests and responses
 */
public class WalletInventoryHandler implements MessageListener {

    /** Create our logger */
    private static final Logger log = LoggerFactory.getLogger(WalletInventoryHandler.class);

    /** Reject message reason codes */
    private static final Map<Integer, String> reasonCodes = new HashMap<>();
    static {
        reasonCodes.put(NetParams.REJECT_MALFORMED, "Malformed");
        reasonCodes.put(NetParams.REJECT_INVALID, "Invalid");
        reasonCodes.put(NetParams.REJECT_OBSOLETE, "Obsolete");
        reasonCodes.put(NetParams.REJECT_DUPLICATE, "Duplicate");
        reasonCodes.put(NetParams.REJECT_NONSTANDARD, "Nonstandard");
        reasonCodes.put(NetParams.REJECT_DUST, "Dust");
        reasonCodes.put(NetParams.REJECT_INSUFFICIENT_FEE, "Insufficient fee");
        reasonCodes.put(NetParams.REJECT_CHECKPOINT, "Checkpoint");
    }

    /**
     * Sends the requested inventory item to the requesting peer.  This method
     * is called when a 'getdata' message is processed.
     *
     * @param       peer            Peer requesting the inventory item
     * @param       type            Type of inventory item (INV_BLOCK or INV_TX)
     * @param       hash            Item hash
     * @return                      TRUE if the item was sent, FALSE if it was not sent
     */
    @Override
    public boolean sendInventory(Peer peer, int type, Sha256Hash hash) {
        boolean invSent = false;
        if (type == NetParams.INV_TX) {
            try {
                SendTransaction sendTx = Parameters.wallet.getSendTx(hash);
                if (sendTx != null) {
                    ByteBuffer buffer = MessageHeader.buildMessage("tx", sendTx.getTxData());
                    Message txMsg = new Message(buffer, peer, MessageHeader.TX_CMD);
                    Parameters.networkHandler.sendMessage(txMsg);
                    invSent = true;
                    log.info(String.format("Transaction sent to peer %s\n  Tx %s",
                                           peer.getAddress().toString(), hash.toString()));
                }
            } catch (WalletException exc) {
                log.error("Unable to retrieve wallet transaction", exc);
            }
        }
        return invSent;
    }

    /**
     * Requests an available inventory item if desired.  This method is
     * called when an 'inv' message is processed.
     *
     * @param       peer            Peer announcing inventory item
     * @param       type            Type of inventory item (INV_BLOCK or INV_TX)
     * @param       hash            Item hash
     */
    @Override
    public void requestInventory(Peer peer, int type, Sha256Hash hash) {
        try {
            switch (type) {
                case NetParams.INV_TX:
                    if (Parameters.wallet.isNewTransaction(hash)) {
                        PeerRequest request = new PeerRequest(hash, NetParams.INV_TX, peer);
                        synchronized(Parameters.lock) {
                            if (!Parameters.pendingRequests.contains(request) &&
                                            !Parameters.processedRequests.contains(request))
                                Parameters.pendingRequests.add(request);
                        }
                    }
                    break;
                case NetParams.INV_BLOCK:
                    if (Parameters.wallet.isNewBlock(hash) ||
                                Parameters.networkChainHeight > Parameters.wallet.getChainHeight()) {
                        PeerRequest request = new PeerRequest(hash, NetParams.INV_FILTERED_BLOCK, peer);
                        synchronized(Parameters.lock) {
                            if (!Parameters.pendingRequests.contains(request) &&
                                            !Parameters.processedRequests.contains(request))
                                Parameters.pendingRequests.add(request);
                        }
                    }
                    break;
            }
        } catch (WalletException exc) {
            log.error("Unable to check wallet status", exc);
        }
    }

    /**
     * Processes request completion.  This method is called when a 'merkleblock'
     *  or 'tx' message is processed.
     *
     * @param       peer            Peer sending the response
     * @param       type            Type of inventory item (INV_FILTERED_BLOCK or INV_TX)
     * @param       hash            Item hash
     */
    @Override
    public void requestCompleted(Peer peer, int type, Sha256Hash hash) {
        synchronized(Parameters.lock) {
            Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
            while (it.hasNext()) {
                PeerRequest request = it.next();
                if (request.getType() == type && request.getHash().equals(hash)) {
                    it.remove();
                    break;
                }
            }
        }
    }

    /**
     * Processes a request that was returned by the peer because the inventory item was
     * not found.  The request can be discarded or retried by sending it to a different
     * peer.  This method is called when a 'notfound' message is processed.
     *
     * @param       peer            Peer sending the response
     * @param       type            Type of inventory item (INV_BLOCK or INV_TX)
     * @param       hash            Item hash
     */
    @Override
    public void requestNotFound(Peer peer, int type, Sha256Hash hash) {
        synchronized(Parameters.lock) {
            Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
            while (it.hasNext()) {
                PeerRequest request = it.next();
                if (request.getType()==type && request.getHash().equals(hash)) {
                    it.remove();
                    Parameters.pendingRequests.add(request);
                    break;
                }
            }
        }
    }

    /**
     * Processes a block header received from a remote peer.  This method is
     * called when a 'headers' or 'merkleblock' message is processed.
     *
     * @param       blockHeader     Block header
     */
    @Override
    public void processBlockHeader(BlockHeader blockHeader) {
        try {
            Parameters.databaseQueue.put(blockHeader);
        } catch (InterruptedException exc) {
            log.error("Thread interrupted while adding to database handler queue", exc);
        }
    }

    /**
     * Processes a transaction received from a remote peer.  This method is
     * called when a 'tx' message is processed
     *
     * @param       tx              Transaction
     */
    @Override
    public void processTransaction(Transaction tx) {
        try {
            Parameters.databaseQueue.put(tx);
        } catch (InterruptedException exc) {
            log.error("Thread interrupted while adding to database handler queue", exc);
        }
    }

    /**
     * Processes a rejection from a peer.  This method is called when a 'reject'
     * message is processed.
     *
     * @param       peer            Peer sending the message
     * @param       cmd             Failing message command
     * @param       reasonCode      Failure reason code
     * @param       description     Description of the failure
     * @param       hash            Item hash
     */
    @Override
    public void processReject(Peer peer, String cmd, int reasonCode, String description, Sha256Hash hash) {
        String reason = reasonCodes.get(reasonCode);
        if (reason == null)
            reason = "N/A";
        log.error(String.format("Message rejected by %s\n  Command %s, Reason %s - %s\n  %s",
                                peer.getAddress().toString(), cmd, reason, description,
                                hash.toString()));
    }
}
