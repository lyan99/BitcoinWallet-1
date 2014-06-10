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
import static org.ScripterRon.BitcoinWallet.Main.log;

import org.ScripterRon.BitcoinCore.AbstractMessageListener;
import org.ScripterRon.BitcoinCore.AddressMessage;
import org.ScripterRon.BitcoinCore.Alert;
import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.NotFoundMessage;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.PongMessage;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionMessage;
import org.ScripterRon.BitcoinCore.VersionAckMessage;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Handle inventory requests and responses
 */
public class WalletMessageListener extends AbstractMessageListener {

    /**
     * Handle an inventory request
     *
     * <p>This method is called when a 'getdata' message is received.  The application
     * should send the inventory items to the requesting peer.  A 'notfound' message
     * should be returned to the requesting peer if one or more items cannot be sent.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    @Override
    public void sendInventory(Message msg, List<InventoryItem> invList) {
        Peer peer = msg.getPeer();
        List<InventoryItem> notFoundList = new ArrayList<>(invList.size());
        //
        // Process the inventory list and request new transactions
        //
        invList.stream().forEach((item) -> {
            switch (item.getType()) {
                case InventoryItem.INV_TX:
                    try {
                        SendTransaction sendTx = Parameters.wallet.getSendTx(item.getHash());
                        if (sendTx != null) {
                            Message txMsg = TransactionMessage.buildTransactionMessage(peer, sendTx.getTxData());
                            Parameters.networkHandler.sendMessage(txMsg);
                            log.info(String.format("Transaction sent to peer %s\n  Tx %s",
                                                   peer.getAddress().toString(), item.getHash().toString()));
                        } else {
                            log.debug(String.format("Requested transaction not found\n  Tx %s",
                                                    item.getHash().toString()));
                            notFoundList.add(item);
                        }
                    } catch (WalletException exc) {
                        log.error("Unable to retrieve wallet transaction", exc);
                        notFoundList.add(item);
                    }
                    break;
                default:
                    notFoundList.add(item);
            }
        });
        //
        // Send a 'notfound' message if we couldn't process all of the requests
        //
        if (!notFoundList.isEmpty()) {
            Message invMsg = NotFoundMessage.buildNotFoundMessage(peer, notFoundList);
            Parameters.networkHandler.sendMessage(invMsg);
        }
    }

    /**
     * Handle an inventory item available notification
     *
     * <p>This method is called when an 'inv' message is received.  The application
     * should request any needed inventory items from the peer.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    @Override
    public void requestInventory(Message msg, List<InventoryItem> invList) {
        Peer peer = msg.getPeer();
        //
        // Process the inventory list and request new transactions and blocks.  We also
        // need to request a block already in our database if we are catching up to the
        // current network height because the previous scan may have been interrupted and
        // the Bloom filter changed.
        //
        invList.stream().forEach((item) -> {
            try {
                switch (item.getType()) {
                    case InventoryItem.INV_TX:
                        if (Parameters.wallet.isNewTransaction(item.getHash())) {
                            PeerRequest request = new PeerRequest(item.getHash(), InventoryItem.INV_TX, peer);
                            synchronized(Parameters.lock) {
                            if (!Parameters.pendingRequests.contains(request) &&
                                            !Parameters.processedRequests.contains(request))
                                Parameters.pendingRequests.add(request);
                            }
                        }
                        break;
                    case InventoryItem.INV_BLOCK:
                        if (Parameters.wallet.isNewBlock(item.getHash()) ||
                                        Parameters.networkChainHeight > Parameters.wallet.getChainHeight()) {
                            PeerRequest request = new PeerRequest(item.getHash(),
                                        InventoryItem.INV_FILTERED_BLOCK, peer);
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
        });
    }

    /**
     * Handle a request not found
     *
     * <p>This method is called when a 'notfound' message is received.  It notifies the
     * application that an inventory request cannot be completed because the item was
     * not found.  The request can be discarded or retried by sending it to a different
     * peer.</p>
     *
     * @param       msg             Message
     * @param       invList         Inventory item list
     */
    @Override
    public void requestNotFound(Message msg, List<InventoryItem> invList) {
        //
        // Process the inventory list and retry the failing requests
        //
        invList.stream().forEach((item) -> {
            synchronized(Parameters.lock) {
                Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
                while (it.hasNext()) {
                    PeerRequest request = it.next();
                    if (request.getType()==item.getType() && request.getHash().equals(item.getHash())) {
                        it.remove();
                        Parameters.pendingRequests.add(request);
                        break;
                    }
                }
            }
        });
    }

    /**
     * Process a peer address list
     *
     * <p>This method is called when an 'addr' message is received.  The address list
     * contains peers that have been active recently.</p>
     *
     * @param       msg             Message
     * @param       addresses       Peer address list
     */
    @Override
    public void processAddresses(Message msg, List<PeerAddress> addresses) {
        //
        // Add the peer address to the front of the address list since they
        // are presumably more current than what we have
        //
        synchronized(Parameters.lock) {
            addresses.stream().forEach((addr) -> {
                PeerAddress chkAddr = Parameters.peerMap.get(addr);
                if (chkAddr != null) {
                    chkAddr.setTimeStamp(addr.getTimeStamp());
                } else {
                    Parameters.peerAddresses.add(0, addr);
                    Parameters.peerMap.put(addr, addr);
                }
            });
        }
    }

    /**
     * Process an alert
     *
     * <p>This method is called when an 'alert' message is received.</p>
     *
     * @param       msg             Message
     * @param       alert           Alert
     */
    @Override
    public void processAlert(Message msg, Alert alert) {
        //
        // Add the alert message to the log
        //
        if (alert.getExpireTime() > System.currentTimeMillis()/1000)
            log.warn(String.format("**** Alert %d ****\n  %s",
                                   alert.getID(), alert.getMessage()));
    }

    /**
     * Process a block header
     *
     * <p>This method is called when a 'headers' message is received.</p>
     *
     * @param       msg             Message
     * @param       hdrList         Block header list
     */
    @Override
    public void processBlockHeaders(Message msg, List<BlockHeader> hdrList) {
        //
        // Add the block headers to the database handler queue for processing
        //
        hdrList.stream().forEach((header) -> {
            try {
                Parameters.databaseQueue.put(header);
            } catch (InterruptedException exc) {
                log.error("Thread interrupted while adding to database handler queue", exc);
            }
        });
    }

    /**
     * Process a get address request
     *
     * <p>This method is called when a 'getaddr' message is received.  The application should
     * call AddressMessage.buildAddressMessage() to build the response message.</p>
     *
     * @param       msg             Message
     */
    @Override
    public void processGetAddress(Message msg) {
        //
        // Send our address list to the requester
        //
        List<PeerAddress> addresses;
        synchronized(Parameters.lock) {
            addresses = new ArrayList<>(Parameters.peerAddresses);
        }
        Message addrMsg = AddressMessage.buildAddressMessage(msg.getPeer(), addresses, null);
        Parameters.networkHandler.sendMessage(addrMsg);
    }

    /**
     * Process a Merkle block
     *
     * <p>This method is called when a 'merkleblock' message is received.</p>
     *
     * @param       msg             Message
     * @param       blkHeader       Merkle block header
     */
    @Override
    public void processMerkleBlock(Message msg, BlockHeader blkHeader) {
        //
        // Add the block header to the database handler queue for processing
        //
        try {
            requestCompleted(InventoryItem.INV_FILTERED_BLOCK, blkHeader.getHash());
            Parameters.databaseQueue.put(blkHeader);
        } catch (InterruptedException exc) {
            log.error("Thread interrupted while adding to database handler queue", exc);
        }
    }

    /**
     * Process a ping
     *
     * <p>This method is called when a 'ping' message is received.  The application should
     * return a 'pong' message to the sender.</p>
     *
     * @param       msg             Message
     * @param       nonce           Nonce
     */
    @Override
    public void processPing(Message msg, long nonce) {
        Message pongMsg = PongMessage.buildPongMessage(msg.getPeer(), nonce);
        Parameters.networkHandler.sendMessage(pongMsg);
    }

    /**
     * Process a pong
     *
     * <p>This method is called when a 'pong' message is received.</p>
     *
     * @param       msg             Message
     * @param       nonce           Nonce
     */
    @Override
    public void processPong(Message msg, long nonce) {
        Peer peer = msg.getPeer();
        peer.setPing(false);
        log.info(String.format("'pong' response received from %s", peer.getAddress().toString()));
    }

    /**
     * Process a message rejection
     *
     * <p>This method is called when a 'reject' message is received.</p>
     *
     * @param       msg             Message
     * @param       cmd             Failing message command
     * @param       reasonCode      Failure reason code
     * @param       description     Description of the failure
     * @param       hash            Item hash or Sha256Hash.ZERO_HASH
     */
    @Override
    public void processReject(Message msg, String cmd, int reasonCode, String description, Sha256Hash hash) {
        String reason = RejectMessage.reasonCodes.get(reasonCode);
        if (reason == null)
            reason = "N/A";
        log.error(String.format("Message rejected by %s\n  Command %s, Reason %s - %s\n  %s",
                                msg.getPeer().getAddress().toString(), cmd, reason, description,
                                hash.toString()));
    }

    /**
     * Process a transaction
     *
     * <p>This method is called when a 'tx' message is received.</p>
     *
     * @param       msg             Message
     * @param       tx              Transaction
     */
    @Override
    public void processTransaction(Message msg, Transaction tx) {
        try {
            requestCompleted(InventoryItem.INV_TX, tx.getHash());
            Parameters.databaseQueue.put(tx);
        } catch (InterruptedException exc) {
            log.error("Thread interrupted while adding to database handler queue", exc);
        }
    }

    /**
     * Process a version message
     *
     * <p>This method is called when a 'version' message is received.  The application
     * should return a 'verack' message to the sender if the connection is accepted.</p>
     *
     * @param       msg             Message
     * @param       localAddress    Local address as seen by the peer
     */
    @Override
    public void processVersion(Message msg, PeerAddress localAddress) {
        Peer peer = msg.getPeer();
        //
        // Disconnect the peer if it doesn't provide node services.  Otherwise, increment
        // the version handshake stage.
        //
        if ((peer.getServices()&NetParams.NODE_NETWORK) == 0) {
            peer.setDisconnect(true);
            log.info(String.format("Connection rejected from %s", peer.getAddress().toString()));
        } else {
            peer.incVersionCount();
            Message ackMsg = VersionAckMessage.buildVersionAckMessage(peer);
            Parameters.networkHandler.sendMessage(ackMsg);
            log.info(String.format("Peer %s: Protocol level %d, Services %d, Agent %s, Height %d",
                    peer.getAddress().toString(), peer.getVersion(), peer.getServices(),
                    peer.getUserAgent(), peer.getHeight()));
        }
    }

    /**
     * Process a version acknowledgment
     *
     * <p>This method is called when a 'verack' message is received.</p>
     *
     * @param       msg             Message
     */
    @Override
    public void processVersionAck(Message msg) {
        //
        // Increment the version handshake stage
        //
        msg.getPeer().incVersionCount();
    }

    /**
     * Process a completed request
     *
     * @param       type            Type of inventory item (INV_FILTERED_BLOCK or INV_TX)
     * @param       hash            Item hash
     */
    private void requestCompleted(int type, Sha256Hash hash) {
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
}
