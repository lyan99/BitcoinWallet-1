/**
 * Copyright 2013-2014 Ronald W Hoffman
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

import org.ScripterRon.BitcoinCore.AddressMessage;
import org.ScripterRon.BitcoinCore.AlertMessage;
import org.ScripterRon.BitcoinCore.GetAddressMessage;
import org.ScripterRon.BitcoinCore.GetDataMessage;
import org.ScripterRon.BitcoinCore.HeadersMessage;
import org.ScripterRon.BitcoinCore.InventoryMessage;
import org.ScripterRon.BitcoinCore.MerkleBlockMessage;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageHeader;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.NotFoundMessage;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.PingMessage;
import org.ScripterRon.BitcoinCore.PongMessage;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.SerializedBuffer;
import org.ScripterRon.BitcoinCore.TransactionMessage;
import org.ScripterRon.BitcoinCore.VerificationException;
import org.ScripterRon.BitcoinCore.VersionAckMessage;
import org.ScripterRon.BitcoinCore.VersionMessage;

import java.io.EOFException;

/**
 * A message handler processes incoming messages on a separate dispatching thread.
 * It creates a response message if needed and then calls the network listener to
 * process the message completion.
 *
 * The message handler continues running until its shutdown() method is called.  It
 * receives messages from the messageQueue list, blocking if necessary until a message
 * is available.
 */
public class MessageHandler implements Runnable {

    /** Message handler thread */
    private Thread handlerThread;

    /** Message handler shutdown */
    private boolean handlerShutdown = false;

    /**
     * Creates a message handler
     */
    public MessageHandler() {
    }

    /**
     * Shuts down the message handler
     */
    public void shutdown() {
        handlerShutdown = true;
        handlerThread.interrupt();
    }

    /**
     * Processes messages and returns responses
     */
    @Override
    public void run() {
        log.info("Message handler started");
        handlerThread = Thread.currentThread();
        //
        // Process messages until we are shutdown
        //
        try {
            while (!handlerShutdown) {
                Message msg = Parameters.messageQueue.take();
                processMessage(msg);
            }
        } catch (InterruptedException exc) {
            if (!handlerShutdown)
                log.warn("Message handler interrupted", exc);
        } catch (Exception exc) {
            log.error("Exception while processing messages", exc);
        }
        //
        // Stopping
        //
        log.info("Message handler stopped");
    }

    /**
     * Process a message and return a response
     *
     * @param       msg             Message
     */
    private void processMessage(Message msg) throws InterruptedException {
        Peer peer = msg.getPeer();
        PeerAddress address = peer.getAddress();
        String cmd = "N/A";
        int reasonCode = 0;
        int cmdOp = 0;
        try {
            SerializedBuffer inBuffer = new SerializedBuffer(msg.getBuffer());
            msg.setBuffer(null);
            //
            // Process the message header and get the command name
            //
            cmd = MessageHeader.processMessage(inBuffer);
            Integer cmdLookup = MessageHeader.cmdMap.get(cmd);
            if (cmdLookup != null)
                cmdOp = cmdLookup;
            else
                cmdOp = 0;
            msg.setCommand(cmdOp);
            log.debug(String.format("Processing '%s' message from %s", cmd, address.toString()));
            //
            // Process the message
            //
            switch (cmdOp) {
                case MessageHeader.VERSION_CMD:
                    //
                    // Process the 'version' message
                    //
                    VersionMessage.processVersionMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.VERACK_CMD:
                    //
                    // Process the 'verack' message
                    //
                    VersionAckMessage.processVersionAckMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.ADDR_CMD:
                    //
                    // Process the 'addr' message
                    //
                    AddressMessage.processAddressMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.INV_CMD:
                    //
                    // Process the 'inv' message
                    //
                    InventoryMessage.processInventoryMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.GETDATA_CMD:
                    //
                    // Process the 'getdata' message
                    //
                    GetDataMessage.processGetDataMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.HEADERS_CMD:
                    //
                    // Process the 'headers' message
                    //
                    HeadersMessage.processHeadersMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.MERKLEBLOCK_CMD:
                    //
                    // Process the 'merkleblock' message
                    //
                    MerkleBlockMessage.processMerkleBlockMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.TX_CMD:
                    //
                    // Process the 'tx' message
                    //
                    TransactionMessage.processTransactionMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.GETADDR_CMD:
                    //
                    // Process the 'getaddr' message
                    //
                    GetAddressMessage.processGetAddressMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.NOTFOUND_CMD:
                    //
                    // Process the 'notfound' message
                    //
                    NotFoundMessage.processNotFoundMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.PING_CMD:
                    //
                    // Process the 'ping' message
                    //
                    PingMessage.processPingMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.PONG_CMD:
                    //
                    // Process the 'pong' message
                    //
                    PongMessage.processPongMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.REJECT_CMD:
                    //
                    // Process the 'reject' message
                    //
                    RejectMessage.processRejectMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                case MessageHeader.ALERT_CMD:
                    //
                    // Process the 'alert' message
                    //
                    AlertMessage.processAlertMessage(msg, inBuffer, Parameters.messageListener);
                    break;
                default:
                    log.error(String.format("Unsupported '%s' message from %s", cmd, address.toString()));
            }
        } catch (EOFException exc) {
            log.error(String.format("End-of-data while processing '%s' message from %s",
                                    cmd, address.toString()), exc);
            reasonCode = NetParams.REJECT_MALFORMED;
            if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode, exc.getMessage());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        } catch (VerificationException exc) {
            log.error(String.format("Message verification failed for '%s' message from %s\n  %s\n  %s",
                                    cmd, address.toString(), exc.getMessage(), exc.getHash().toString()));
            if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            reasonCode = exc.getReason();
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode,
                                                                     exc.getMessage(), exc.getHash());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        }
        //
        // Add the message to the completed message list and wakeup the network listener.  We will
        // bump the banscore for the peer if the message was rejected because it was malformed
        // or invalid.
        //
        synchronized(Parameters.lock) {
            Parameters.completedMessages.add(msg);
            if (reasonCode != 0) {
                if (reasonCode == NetParams.REJECT_MALFORMED || reasonCode == NetParams.REJECT_INVALID) {
                    int banScore = peer.getBanScore() + 5;
                    peer.setBanScore(banScore);
                    if (banScore >= Parameters.MAX_BAN_SCORE)
                        peer.setDisconnect(true);
                }
            }
        }
        Parameters.networkHandler.wakeup();
    }
}
