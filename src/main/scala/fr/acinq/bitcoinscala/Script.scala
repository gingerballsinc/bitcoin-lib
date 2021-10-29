package fr.acinq.bitcoinscala

import fr.acinq.bitcoin
import fr.acinq.bitcoinscala.Crypto._
import fr.acinq.bitcoinscala.KotlinUtils._
import scodec.bits.ByteVector

import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * script execution flags
 */
object ScriptFlags {
  val SCRIPT_VERIFY_NONE = bitcoin.ScriptFlags.SCRIPT_VERIFY_NONE

  // Evaluate P2SH subscripts (softfork safe, BIP16).
  val SCRIPT_VERIFY_P2SH = bitcoin.ScriptFlags.SCRIPT_VERIFY_P2SH

  // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
  // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
  // (softfork safe, but not used or intended as a consensus rule).
  val SCRIPT_VERIFY_STRICTENC = bitcoin.ScriptFlags.SCRIPT_VERIFY_STRICTENC

  // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
  val SCRIPT_VERIFY_DERSIG = bitcoin.ScriptFlags.SCRIPT_VERIFY_DERSIG

  // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
  // (softfork safe, BIP62 rule 5).
  val SCRIPT_VERIFY_LOW_S = bitcoin.ScriptFlags.SCRIPT_VERIFY_LOW_S

  // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
  val SCRIPT_VERIFY_NULLDUMMY = bitcoin.ScriptFlags.SCRIPT_VERIFY_NULLDUMMY

  // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
  val SCRIPT_VERIFY_SIGPUSHONLY = bitcoin.ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY

  // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
  // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
  // any other push causes the script to fail (BIP62 rule 3).
  // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
  // (softfork safe)
  val SCRIPT_VERIFY_MINIMALDATA = bitcoin.ScriptFlags.SCRIPT_VERIFY_MINIMALDATA

  // Discourage use of NOPs reserved for upgrades (NOP1-10)
  //
  // Provided so that nodes can avoid accepting or mining transactions
  // containing executed NOP's whose meaning may change after a soft-fork,
  // thus rendering the script invalid; with this flag set executing
  // discouraged NOPs fails the script. This verification flag will never be
  // a mandatory flag applied to scripts in a block. NOPs that are not
  // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
  val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = bitcoin.ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS

  // Require that only a single stack element remains after evaluation. This changes the success criterion from
  // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
  // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
  // (softfork safe, BIP62 rule 6)
  // Note: CLEANSTACK should never be used without P2SH.
  val SCRIPT_VERIFY_CLEANSTACK = bitcoin.ScriptFlags.SCRIPT_VERIFY_CLEANSTACK

  // Verify CHECKLOCKTIMEVERIFY
  //
  // See BIP65 for details.
  val SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = bitcoin.ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY


  // See BIP112 for details
  val SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = bitcoin.ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

  // support CHECKSEQUENCEVERIFY opcode
  //
  // Support segregated witness
  //
  val SCRIPT_VERIFY_WITNESS = bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS

  // Making v2-v16 witness program non-standard
  //
  val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = bitcoin.ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM


  // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
  //
  val SCRIPT_VERIFY_MINIMALIF = bitcoin.ScriptFlags.SCRIPT_VERIFY_MINIMALIF

  // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
  //
  val SCRIPT_VERIFY_NULLFAIL = bitcoin.ScriptFlags.SCRIPT_VERIFY_NULLFAIL

  // Public keys in segregated witness scripts must be compressed
  //
  val SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE

  // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
  //
  val SCRIPT_VERIFY_CONST_SCRIPTCODE = bitcoin.ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE

  /**
   * Mandatory script verification flags that all new blocks must comply with for
   * them to be valid. (but old blocks may not comply with) Currently just P2SH,
   * but in the future other flags may be added, such as a soft-fork to enforce
   * strict DER encoding.
   *
   * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
   * details.
   */
  val MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH

  /**
   * Standard script verification flags that standard transactions will comply
   * with. However scripts violating these flags may still be present in valid
   * blocks and we must accept those blocks.
   */
  val STANDARD_SCRIPT_VERIFY_FLAGS = bitcoin.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS

  /** For convenience, standard but not mandatory verify flags. */
  val STANDARD_NOT_MANDATORY_VERIFY_FLAGS = bitcoin.ScriptFlags.STANDARD_NOT_MANDATORY_VERIFY_FLAGS
}

object Script {

  import ScriptFlags._

  def parse(blob: ByteVector): List[ScriptElt] = parse(blob.toArray)

  def parse(blob: Array[Byte]): List[ScriptElt] = bitcoin.Script.parse(blob).asScala.toList.map(kmp2scala)

  def write(script: Seq[ScriptElt]): ByteVector = ByteVector.view(bitcoin.Script.write(script.map(scala2kmp).asJava))

  def encodeNumber(value: Long): ByteVector = ByteVector.view(bitcoin.Script.encodeNumber(value).toByteArray)

  def decodeNumber(input: ByteVector, checkMinimalEncoding: Boolean, maximumSize: Int = 4): Long = bitcoin.Script.decodeNumber(input.toArray, checkMinimalEncoding, maximumSize)

  def isSimpleValue(op: ScriptElt): Boolean = bitcoin.Script.isSimpleValue(op)

  def simpleValue(op: ScriptElt): Byte = bitcoin.Script.simpleValue(op)

  def isPushOnly(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isPushOnly(script.map(scala2kmp).asJava)
  
  def isPayToScript(script: ByteVector): Boolean = bitcoin.Script.isPayToScript(script.toArray)
  
  def isNativeWitnessScript(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isNativeWitnessScript(script.map(scala2kmp).asJava)

  def isNativeWitnessScript(script: ByteVector): Boolean = isNativeWitnessScript(parse(script))

  def checkLockTime(lockTime: Long, tx: Transaction, inputIndex: Int): Boolean = bitcoin.Script.INSTANCE.checkLockTime(lockTime, tx, inputIndex)

  def checkSequence(sequence: Long, tx: Transaction, inputIndex: Int): Boolean = bitcoin.Script.INSTANCE.checkSequence(sequence, tx, inputIndex)

  /**
   * Execution context of a tx script. A script is always executed in the "context" of a transaction that is being
   * verified.
   *
   * @param tx         transaction that is being verified
   * @param inputIndex 0-based index of the tx input that is being processed
   */
  case class Context(tx: Transaction, inputIndex: Int, amount: Satoshi) {
    require(inputIndex >= 0 && inputIndex < tx.txIn.length, "invalid input index")
  }

  /**
   * Bitcoin script runner
   *
   * @param context    script execution context
   * @param scriptFlag script flags
   */
  class Runner(context: Context, scriptFlag: Int = MANDATORY_SCRIPT_VERIFY_FLAGS) {

    private val runner = new bitcoin.Script.Runner(
      new bitcoin.Script.Context(context.tx, context.inputIndex, context.amount), scriptFlag, null
    )


    def verifyWitnessProgram(witness: ScriptWitness, witnessVersion: Long, program: ByteVector): Unit = runner.verifyWitnessProgram(witness, witnessVersion, program.toArray)

    def verifyScripts(scriptSig: ByteVector, scriptPubKey: ByteVector): Boolean = verifyScripts(scriptSig, scriptPubKey, ScriptWitness.empty)

    /**
     * verify a script sig/script pubkey pair:
     * <ul>
     * <li>parse and run script sig</li>
     * <li>parse and run script pubkey using the stack generated by the previous step</li>
     * <li>check the final stack</li>
     * <li>extract and run embedded pay2sh scripts if any and check the stack again</li>
     * </ul>
     *
     * @param scriptSig    signature script
     * @param scriptPubKey public key script
     * @return true if the scripts were successfully verified
     */
    def verifyScripts(scriptSig: ByteVector, scriptPubKey: ByteVector, witness: ScriptWitness): Boolean = runner.verifyScripts(scriptSig, scriptPubKey, witness)
  }
  /**
   * extract a public key hash from a public key script
   *
   * @param script public key script
   * @return the public key hash wrapped in the script
   */
  def publicKeyHash(script: List[ScriptElt]): ByteVector = script match {
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: OP_NOP :: Nil => data // non standard pay to pubkey...
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil => data // standard pay to pubkey
    case OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUAL :: Nil if data.size == 20 => data // standard pay to script
  }

  def publicKeyHash(script: ByteVector): ByteVector = publicKeyHash(parse(script))

  /**
   * extract a public key from a signature script
   *
   * @param script signature script
   * @return the public key wrapped in the script
   */
  def publicKey(script: List[ScriptElt]): ByteVector = script match {
    case OP_PUSHDATA(data1, _) :: OP_PUSHDATA(data2, _) :: Nil if data1.length > 2 && data2.length > 2 => data2
    case OP_PUSHDATA(data, _) :: OP_CHECKSIG :: Nil => data
  }

  /**
   * Creates a m-of-n multisig script.
   *
   * @param m       is the number of required signatures
   * @param pubkeys are the public keys signatures will be checked against (there should be at least as many public keys
   *                as required signatures)
   * @return a multisig redeem script
   */
  def createMultiSigMofN(m: Int, pubkeys: Seq[PublicKey]): Seq[ScriptElt] = {
    require(m > 0 && m <= 16, s"number of required signatures is $m, should be between 1 and 16")
    require(pubkeys.nonEmpty && pubkeys.size <= 16, s"number of public keys is ${pubkeys.size}, should be between 1 and 16")
    require(m <= pubkeys.size, "The required number of signatures shouldn't be greater than the number of public keys")
    val op_m = ScriptElt.code2elt(m + 0x50)
    // 1 -> OP_1, 2 -> OP_2, ... 16 -> OP_16
    val op_n = ScriptElt.code2elt(pubkeys.size + 0x50)
    op_m :: pubkeys.toList.map(pub => OP_PUSHDATA(pub.value)) ::: op_n :: OP_CHECKMULTISIG :: Nil
  }

  /**
   * @param pubKeyHash public key hash
   * @return a pay-to-public-key-hash script
   */
  def pay2pkh(pubKeyHash: ByteVector): Seq[ScriptElt] = bitcoin.Script.pay2pkh(pubKeyHash.toArray).asScala.map(kmp2scala).toList

  /**
   * @param pubKey public key
   * @return a pay-to-public-key-hash script
   */
  def pay2pkh(pubKey: PublicKey): Seq[ScriptElt] = pay2pkh(pubKey.hash160)

  def isPay2pkh(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isPay2pkh(script.map(scala2kmp).asJava)

  /**
   * @param script bitcoin script
   * @return a pay-to-script script
   */
  def pay2sh(script: Seq[ScriptElt]): Seq[ScriptElt] = pay2sh(Script.write(script))

  /**
   * @param script bitcoin script
   * @return a pay-to-script script
   */
  def pay2sh(script: ByteVector): Seq[ScriptElt] = bitcoin.Script.pay2sh(script.toArray).asScala.map(kmp2scala).toList

  def isPay2sh(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isPay2sh(script.map(scala2kmp).asJava)

  /**
   * @param script bitcoin script
   * @return a pay-to-witness-script script
   */
  def pay2wsh(script: Seq[ScriptElt]): Seq[ScriptElt] = pay2wsh(Script.write(script))

  /**
   * @param script bitcoin script
   * @return a pay-to-witness-script script
   */
  def pay2wsh(script: ByteVector): Seq[ScriptElt] = bitcoin.Script.pay2wsh(script.toArray).asScala.map(kmp2scala).toList

  def isPay2wsh(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isPay2wsh(script.map(scala2kmp).asJava)

  /**
   * @param pubKeyHash public key hash
   * @return a pay-to-witness-public-key-hash script
   */
  def pay2wpkh(pubKeyHash: ByteVector): Seq[ScriptElt] = bitcoin.Script.pay2wpkh(pubKeyHash.toArray).asScala.map(kmp2scala).toList

  /**
   * @param pubKey public key
   * @return a pay-to-witness-public-key-hash script
   */
  def pay2wpkh(pubKey: PublicKey): Seq[ScriptElt] = pay2wpkh(pubKey.hash160)

  def isPay2wpkh(script: Seq[ScriptElt]): Boolean = bitcoin.Script.isPay2wsh(script.map(scala2kmp).asJava)

  /**
   * @param pubKey public key
   * @param sig    signature matching the public key
   * @return script witness for the corresponding pay-to-witness-public-key-hash script
   */
  def witnessPay2wpkh(pubKey: PublicKey, sig: ByteVector): ScriptWitness = bitcoin.Script.witnessPay2wpkh(pubKey, sig)

  /**
   * @param pubKeys are the public keys signatures will be checked against.
   * @param sigs    are the signatures for a subset of the public keys.
   * @return script witness for the pay-to-witness-script-hash script containing a multisig script.
   */
  def witnessMultiSigMofN(pubKeys: Seq[PublicKey], sigs: Seq[ByteVector]): ScriptWitness = {
    val redeemScript = Script.write(Script.createMultiSigMofN(sigs.size, pubKeys))
    ScriptWitness(ByteVector.empty +: sigs :+ redeemScript)
  }

}
