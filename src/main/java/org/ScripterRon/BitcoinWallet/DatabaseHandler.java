/**
 * Copyright 2013-2017 Ronald W Hoffman
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

import org.ScripterRon.BitcoinCore.Address;
import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.ECKey;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.OutPoint;
import org.ScripterRon.BitcoinCore.ScriptOpCodes;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionInput;
import org.ScripterRon.BitcoinCore.TransactionOutput;
import org.ScripterRon.BitcoinCore.VerificationException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import org.ScripterRon.BitcoinCore.Script;

/**
 * The database handler processes blocks and transactions and updates the wallet database.
 *
 * The database handler continues running until its shutdown() method is called.  It
 * receives blocks and transactions from the databaseQueue list, blocking if necessary
 * until data is available.
 */
public class DatabaseHandler implements Runnable {

    /** Database handler thread */
    private Thread handlerThread;

    /** Database handler shutdown */
    private boolean handlerShutdown = false;

    /** Transaction map */
    private final Map<Sha256Hash, Sha256Hash> txMap = new HashMap<>(50);

    /** Wallet listeners */
    List<WalletListener> listeners = new LinkedList<>();

    /** Block chain rescan height */
    private int rescanHeight = 0;

    /**
     * Creates a database handler
     */
    public DatabaseHandler() {
    }

    /**
     * Shuts down the database handler
     */
    public void shutdown() {
        handlerShutdown = true;
        handlerThread.interrupt();
    }

    /**
     * Adds a wallet listener
     *
     * @param       listener        Wallet listener
     */
    public void addListener(WalletListener listener) {
        listeners.add(listener);
    }

    /**
     * Rescan the block chain starting with the latest block that is before the
     * specified time
     *
     * @param       rescanTime          Rescan time in seconds
     * @throws      WalletException     Unable to scan block chain
     */
    public void rescanChain(long rescanTime) throws WalletException {
        //
        // Get the chain height of the latest block before the rescan time
        //
        rescanHeight = Parameters.wallet.getRescanHeight(rescanTime);
        //
        // Issue a 'getdata' request for the first block
        //
        if (rescanHeight > 0) {
            log.info(String.format("Block chain rescan started at height %d", rescanHeight));
            Sha256Hash blockHash = Parameters.wallet.getBlockHash(rescanHeight);
            PeerRequest request = new PeerRequest(blockHash, InventoryItem.INV_FILTERED_BLOCK);
            synchronized(Parameters.lock) {
                Parameters.pendingRequests.add(request);
            }
            Parameters.networkHandler.wakeup();
        }
    }

    /**
     * Processes blocks and transactions until stopped
     */
    @Override
    public void run() {
        log.info("Database handler started");
        handlerThread = Thread.currentThread();
        //
        // Process blocks and transactions until we are shutdown
        //
        try {
            while (!handlerShutdown) {
                Object obj = Parameters.databaseQueue.take();
                if (obj instanceof BlockHeader) {
                    processBlock(new StoredHeader((BlockHeader)obj));
                    if (Parameters.databaseQueue.isEmpty()) {
                        if (Parameters.wallet.getChainHeight() >= Parameters.networkChainHeight)
                            Parameters.loadingChain = false;
                        else
                            Parameters.networkHandler.getBlocks();
                    }
                } else if (obj instanceof Transaction) {
                    processTransaction((Transaction)obj);
                }
            }
        } catch (InterruptedException exc) {
            if (!handlerShutdown)
                log.warn("Database handler interrupted", exc);
        } catch (Exception exc) {
            log.error("Exception while processing request", exc);
        }
        //
        // Stopping
        //
        log.info("Database handler stopped");
    }

    /**
     * Processes a block
     *
     * @param       blockHeader         Block header
     */
    private void processBlock(StoredHeader blockHeader) {
        Sha256Hash blockHash = blockHeader.getHash();
        try {
            //
            // Update the transaction map with the new transactions.  This allows us to
            // match transactions to this block and is necessary if the block is added to
            // the chain before we receive the transactions (this is the normal case since
            // the peer sends the transactions after sending the merkle block).
            //
            synchronized(Parameters.lock) {
                List<Sha256Hash> matches = blockHeader.getMatches();
                if (matches != null) {
                    for (Sha256Hash txHash : matches) {
                        if (Parameters.wallet.isNewTransaction(txHash))
                            txMap.put(txHash, blockHash);
                    }
                }
            }
            //
            // Process the block
            //
            if (Parameters.wallet.isNewBlock(blockHash)) {
                //
                // This is a new block, so store the block in the wallet database
                // and update the chain
                //
                Parameters.wallet.storeHeader(blockHeader);
                updateChain(blockHeader);
                if (blockHeader.isOnChain()) {
                    Sha256Hash parentHash = blockHash;
                    while (parentHash != null)
                        parentHash = processChildBlock(parentHash);
                }
            } else {
                //
                // The block already exists, so just update the matched transactions
                //
                Parameters.wallet.updateMatches(blockHeader);
                if (rescanHeight != 0) {
                    //
                    // We are doing a rescan, so request the next block in the chain
                    //
                    rescanHeight++;
                    if (rescanHeight > Parameters.wallet.getChainHeight()) {
                        rescanHeight = 0;
                        log.info("Block rescan completed");
                        listeners.forEach((listener) -> listener.rescanCompleted());
                    } else {
                        if (rescanHeight%1000 == 0)
                            log.debug(String.format("Block rescan at block %d", rescanHeight));
                        Sha256Hash nextHash = Parameters.wallet.getBlockHash(rescanHeight);
                        PeerRequest request = new PeerRequest(nextHash, InventoryItem.INV_FILTERED_BLOCK);
                        synchronized(Parameters.lock) {
                            Parameters.pendingRequests.add(request);
                        }
                        Parameters.networkHandler.wakeup();
                    }
                } else {
                    //
                    // See if this block is on the chain.  If it isn't, update the chain.
                    //
                    StoredHeader chkHeader = Parameters.wallet.getHeader(blockHash);
                    if (!chkHeader.isOnChain()) {
                        updateChain(blockHeader);
                        if (blockHeader.isOnChain()) {
                            Sha256Hash parentHash = blockHash;
                            while (parentHash != null)
                                parentHash = processChildBlock(parentHash);
                        }
                    }
                }
            }
        } catch (BlockNotFoundException exc) {
            PeerRequest request = new PeerRequest(exc.getHash(), InventoryItem.INV_FILTERED_BLOCK);
            boolean wakeup = false;
            synchronized(Parameters.lock) {
                if (!Parameters.pendingRequests.contains(request) && !Parameters.processedRequests.contains(request)) {
                    Parameters.pendingRequests.add(request);
                    wakeup = true;
                }
            }
            if (wakeup)
                Parameters.networkHandler.wakeup();
        } catch (VerificationException exc) {
            log.error(String.format("Checkpoint verification failed\n  %s", exc.getHash()), exc);
        } catch (WalletException exc) {
            log.error(String.format("Unable to process block\n  %s", blockHash.toString()), exc);
        }
    }

    /**
     * Updates the chain with the new block
     *
     * @param       blockHeader             Block being added
     * @throws      VerificationException   Checkpoint verification failed
     * @throws      WalletException         Unable to process the block
     */
    private void updateChain(StoredHeader blockHeader) throws VerificationException, WalletException {
        //
        // Locate the junction block for the chain represented by this block
        //
        List<StoredHeader> chainList = Parameters.wallet.getJunction(blockHeader.getPrevHash());
        chainList.add(blockHeader);
        //
        // Update chain work and block height for each block in the new chain
        //
        StoredHeader chainHeader = chainList.get(0);
        BigInteger chainWork = chainHeader.getChainWork();
        int blockHeight = chainHeader.getBlockHeight();
        for (int i=1; i<chainList.size(); i++) {
            chainHeader = chainList.get(i);
            chainWork = chainWork.add(chainHeader.getBlockWork());
            chainHeader.setChainWork(chainWork);
            chainHeader.setBlockHeight(++blockHeight);
        }
        //
        // Make this block the new chain head if it is a better chain than the current chain.
        // This means the cumulative chain work is greater.
        //
        if (blockHeader.getChainWork().compareTo(Parameters.wallet.getChainWork()) > 0) {
            Parameters.wallet.setChainHead(chainList);
            for (int i=1; i<chainList.size(); i++) {
                chainHeader = chainList.get(i);
                chainHeader.setChain(true);
                for (WalletListener listener : listeners)
                    listener.addChainBlock(chainHeader);
            }
            Parameters.networkChainHeight = Math.max(Parameters.networkChainHeight, blockHeader.getBlockHeight());
        } else {
            log.debug(String.format("Block not added to chain: New chain work %d, Current chain work %d\n  Block %s",
                                    blockHeader.getChainWork(), Parameters.wallet.getChainWork(), blockHeader.getHash()));
        }
    }

    /**
     * Process a child block and see if it can now be added to the chain.  This happens
     * if we are unable to resolve a chain because we are missing a block and have to
     * ask a peer to send us the block.
     *
     * @param       parentHash              Parent block hash
     * @throws      VerificationException   Checkpoint verification failed
     * @throws      WalletException         Unable to process child block
     */
    private Sha256Hash processChildBlock(Sha256Hash parentHash) throws VerificationException, WalletException {
        Sha256Hash nextParent = null;
        StoredHeader childHeader = Parameters.wallet.getChildHeader(parentHash);
        if (childHeader != null && !childHeader.isOnChain()) {
            updateChain(childHeader);
            if (childHeader.isOnChain()) {
                nextParent = childHeader.getHash();
            }
        }
        return nextParent;
    }

    /**
     * Processes a transaction received from the network or created by the wallet
     *
     * @param       tx                  Transaction
     */
    public void processTransaction(Transaction tx) {
        Sha256Hash txHash = tx.getHash();
        Sha256Hash blockHash;
        long txTime;
        boolean txUpdated = false;
        try {
            //
            // Get the block containing this transaction.  If the block is
            // on the chain, we will add the block hash to the transaction
            // entries that we create to indicate they have been confirmed.
            //
            synchronized(Parameters.lock) {
                blockHash = txMap.get(txHash);
                if (blockHash != null)
                    txMap.remove(txHash);
            }
            if (blockHash != null) {
                StoredHeader blockHeader = Parameters.wallet.getHeader(blockHash);
                txTime = blockHeader.getBlockTime();
                if (!blockHeader.isOnChain())
                    blockHash = null;
            } else {
                txTime = System.currentTimeMillis()/1000;
            }
            //
            // Process the transaction
            //
            if (Parameters.wallet.isNewTransaction(txHash)) {
                //
                // See if the transaction is sending us coins by checking the outputs.
                // We need to check each output since we could be sending coins
                // to ourself, in which case two outputs will be of interest.
                //
                List<TransactionOutput> txOutputs = tx.getOutputs();
                BigInteger totalValue = BigInteger.ZERO;
                BigInteger totalChange = BigInteger.ZERO;
                for (int txIndex=0; txIndex<txOutputs.size(); txIndex++) {
                    TransactionOutput txOutput = txOutputs.get(txIndex);
                    totalValue = totalValue.add(txOutput.getValue());
                    ECKey key = (ECKey)checkAddress(txOutput, true);
                    if (key != null) {
                        if (key.isChange())
                            totalChange = totalChange.add(txOutput.getValue());
                        ReceiveTransaction rcvTx = new ReceiveTransaction(tx.getNormalizedID(),
                                txHash, txIndex, txTime, blockHash, key.toAddress(), txOutput.getValue(),
                                txOutput.getScriptBytes(), key.isChange(), tx.isCoinBase());
                        Parameters.wallet.storeReceiveTx(rcvTx);
                        txUpdated = true;
                    }
                }
                //
                // Mark the connected output as spent if this transaction is spending our coins
                //
                boolean isRelevant = false;
                List<ReceiveTransaction> rcvList = Parameters.wallet.getReceiveTxList();
                List<TransactionInput> txInputs = tx.getInputs();
                BigInteger totalInput = BigInteger.ZERO;
                for (TransactionInput txInput : txInputs) {
                    OutPoint txOutPoint = txInput.getOutPoint();
                    for (ReceiveTransaction rcv : rcvList) {
                        if (rcv.getTxHash().equals(txOutPoint.getHash()) &&
                                                    rcv.getTxIndex() == txOutPoint.getIndex()) {
                            totalInput = totalInput.add(rcv.getValue());
                            Parameters.wallet.setTxSpent(rcv.getTxHash(), rcv.getTxIndex(), true);
                            isRelevant = true;
                            txUpdated = true;
                            break;
                        }
                    }
                }
                //
                // Create a database entry for this transaction if it spent any of our coins.
                // We will use the non-change output as the destination and set the timestamp back
                // by 15 seconds so that the send transaction will be sorted before the receive
                // transaction in case we are sending the coins to ourself.
                //
                if (isRelevant) {
                    Address address = null;
                    for (TransactionOutput txOutput : txOutputs) {
                        address = (Address)checkAddress(txOutput, false);
                        if (address != null)
                            break;
                    }
                    if (address != null) {
                        BigInteger fee = totalInput.subtract(totalValue);
                        BigInteger sentValue = totalValue.subtract(totalChange);
                        SendTransaction sendTx = new SendTransaction(tx.getNormalizedID(), txHash,
                                txTime-15, blockHash, address, sentValue, fee,
                                (tx.isWitness() ? tx.getWitnessBytes() : tx.getBytes()));
                        Parameters.wallet.storeSendTx(sendTx);
                    }
                }
                //
                // Notify any listeners that one or more transactions have been updated
                //
                if (txUpdated)
                    listeners.forEach((listener) -> listener.txUpdated());
            }
        } catch (WalletException exc) {
            log.error(String.format("Unable to process transaction\n  %s", txHash), exc);
        }
    }

    /**
     * Checks the transaction output for one of our addresses.
     *
     * If 'ourAddress' is TRUE, we will return the ECKey if the address is one of ours.
     *
     * If 'ourAddress' is FALSE, we will return the Address if it is not a change address
     *
     * @param       txOutput            Transaction output
     * @param       ourAddress          TRUE to look for our address
     * @return                          ECKey/Address or null if no match found
     */
    private Object checkAddress(TransactionOutput txOutput, boolean ourAddress) {
        Object result = null;
        byte[] scriptBytes = txOutput.getScriptBytes();
        int paymentType = Script.getPaymentType(scriptBytes);
        if (paymentType == ScriptOpCodes.PAY_TO_PUBKEY_HASH) {
            //
            // Check PAY_TO_PUBKEY_HASH output script
            //
            byte[] pubKeyHash = Arrays.copyOfRange(scriptBytes, 3, 23);
            synchronized(Parameters.lock) {
                for (ECKey chkKey : Parameters.keys) {
                    if (Arrays.equals(chkKey.getPubKeyHash(), pubKeyHash)) {
                        result = chkKey;
                        break;
                    }
                }
            }
            if (!ourAddress) {
                if (result == null)
                    result = new Address(Address.AddressType.P2PKH, pubKeyHash);
                else if (((ECKey)result).isChange())
                    result = null;
                else
                    result = new Address(Address.AddressType.P2PKH, pubKeyHash);
            }
        } else if (paymentType == ScriptOpCodes.PAY_TO_SCRIPT_HASH) {
            //
            // Check PAY_TO_SCRIPT_HASH output script
            //
            byte[] scriptHash = Arrays.copyOfRange(scriptBytes, 2, 22);
            synchronized(Parameters.lock) {
                for (ECKey chkKey : Parameters.keys) {
                    if (Arrays.equals(chkKey.getScriptHash(), scriptHash)) {
                        result = chkKey;
                        break;
                    }
                }
            }
            if (!ourAddress) {
                if (result == null)
                    result = new Address(Address.AddressType.P2SH, scriptHash);
                else if (((ECKey)result).isChange())
                    result = null;
                else
                    result = new Address(Address.AddressType.P2SH, scriptHash);
            }
        }
        return result;
    }
}
