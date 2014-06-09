/*
 * Copyright 2014 Ronald Hoffman.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ScripterRon.BitcoinWallet;

import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.Sha256Hash;

import java.math.BigInteger;
import java.util.List;

/**
 * StoredHeader represents a block header stored in the database
 */
public class StoredHeader {

    /** Block header */
    private final BlockHeader blockHeader;

    /** On chain */
    private boolean onChain;

    /** Block height */
    private int blockHeight;

    /** Cumulative chain work */
    private BigInteger chainWork;

    /**
     * Create a StoredHeader from a database entry
     *
     * @param       blockHash           Block hash
     * @param       prevHash            Previous block hash
     * @param       blockTime           Time block was mined (seconds since Unix epoch)
     * @param       targetDifficulty    Target difficulty
     * @param       merkleRoot          Merkle root
     * @param       onChain             TRUE if the block is on the block chain
     * @param       blockHeight         Block height
     * @param       chainWork           Cumulative chain work
     * @param       matches             Matched transactions for this block
     */
    public StoredHeader(Sha256Hash blockHash, Sha256Hash prevHash, long blockTime, long targetDifficulty,
                                Sha256Hash merkleRoot, boolean onChain, int blockHeight, BigInteger chainWork,
                                List<Sha256Hash> matches) {
        blockHeader = new BlockHeader(0, blockHash, prevHash, blockTime, targetDifficulty, merkleRoot, 0);
        blockHeader.setMatches(matches);
        this.onChain = onChain;
        this.blockHeight = blockHeight;
        this.chainWork = chainWork;
    }

    /**
     * Return the block header
     *
     * @return                          Block header
     */
    public BlockHeader getHeader() {
        return blockHeader;
    }

    /**
     * Checks if the block is on the block chain
     *
     * @return                          TRUE if the block is on the block chain
     */
    public boolean isOnChain() {
        return onChain;
    }

    /**
     * Sets the block chain status
     *
     * @param       onChain             TRUE if the block is on the block chain
     */
    public void setChain(boolean onChain) {
        this.onChain = onChain;
    }

    /**
     * Returns the block height
     *
     * @return                          Block height
     */
    public int getBlockHeight() {
        return blockHeight;
    }

    /**
     * Sets the block height
     *
     * @param       blockHeight         Block height
     */
    public void setBlockHeight(int blockHeight) {
        this.blockHeight = blockHeight;
    }

    /**
     * Returns the cumulative chain work for this block
     *
     * @return                          Chain work
     */
    public BigInteger getChainWork() {
        return chainWork;
    }

    /**
     * Sets the cumulative chain work for this block
     *
     * @param       chainWork           Chain work
     */
    public void setChainWork(BigInteger chainWork) {
        this.chainWork = chainWork;
    }

    /**
     * Returns the block hash
     *
     * @return                          Block hash
     */
    public Sha256Hash getHash() {
        return blockHeader.getHash();
    }

    /**
     * Returns the previous block hash
     *
     * @return                          Previous block hash
     */
    public Sha256Hash getPrevHash() {
        return blockHeader.getPrevHash();
    }

    /**
     * Returns the block time
     *
     * @return                          Block time
     */
    public long getBlockTime() {
        return blockHeader.getBlockTime();
    }

    /**
     * Returns the Merkle root
     *
     * @return                          Merkle root
     */
    public Sha256Hash getMerkleRoot() {
        return blockHeader.getMerkleRoot();
    }

    /**
     * Returns the target difficulty
     *
     * @return                          Target difficulty
     */
    public long getTargetDifficulty() {
        return blockHeader.getTargetDifficulty();
    }

    /**
     * Returns the block work
     *
     * @return                          Block work
     */
    public BigInteger getBlockWork() {
        return blockHeader.getBlockWork();
    }

    /**
     * Returns the list of matched transactions or null if there are no matched transactions
     *
     * @return                          List of matched transactions
     */
    public List<Sha256Hash> getMatches() {
        return blockHeader.getMatches();
}

    /**
     * Sets the list of matched transactions
     *
     * @param       matches             List of matched transactions or null if there are no matched transactions
     */
    public void setMatches(List<Sha256Hash> matches) {
        blockHeader.setMatches(matches);
    }
}
