package org.ergoplatform.nodeView.state

import org.ergoplatform.ErgoBox
import org.ergoplatform.settings.{Algos, ErgoSettings, LaunchParameters, Parameters}
import scorex.core.{NodeViewComponent, VersionTag}
import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest32
import scorex.db.LDBVersionedStore
import scorex.util.ScorexLogging

/**
  * State-related data and functions related to any state implementation ("utxo" or "digest") which are
  * not modifying the state (so only reading it)
  */
trait ErgoStateReader extends NodeViewComponent with ScorexLogging {

  /**
   * Root hash and height of AVL+ tree authenticating UTXO set
   */
  def rootDigest: ADDigest

  /**
    * Current version of the state
    * Must be ID of last block applied
    */
  def version: VersionTag

  val store: LDBVersionedStore

  protected def ergoSettings: ErgoSettings

  /**
    * If the state is in its genesis version (before genesis block)
    */
  def isGenesis: Boolean = {
    rootDigest.sameElements(ergoSettings.chainSettings.genesisStateDigest)
  }

  /**
    * Blockchain-derived context used in scripts validation. It changes from block to block.
    */
  def stateContext: ErgoStateContext = ErgoStateReader.storageStateContext(store, ergoSettings)

  /**
    * @return current network parameters used in transaction and block validation (block cost and size limits etc)
    */
  def parameters: Parameters = stateContext.currentParameters

  /**
    * Genesis state boxes, see `ErgoState.genesisBoxes` for details
    */
  def genesisBoxes: Seq[ErgoBox] = ErgoState.genesisBoxes(ergoSettings.chainSettings)

}

object ErgoStateReader extends ScorexLogging {

  val ContextKey: Digest32 = Algos.hash("current state context")

  /**
    * Read blockchain-related state context from `store` database
    */
  def storageStateContext(store: LDBVersionedStore, settings: ErgoSettings): ErgoStateContext = {
    store.get(ErgoStateReader.ContextKey)
      .flatMap(b => ErgoStateContextSerializer(settings).parseBytesTry(b).toOption)
      .getOrElse {
        log.warn("Can't read blockchain parameters from database")
        ErgoStateContext.empty(settings, LaunchParameters)
      }
  }

}
