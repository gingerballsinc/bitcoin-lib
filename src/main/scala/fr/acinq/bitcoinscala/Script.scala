package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.Crypto._
import KotlinUtils._
import scodec.bits.ByteVector

import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

/**
 * script execution flags
 */
object ScriptFlags {
  val SCRIPT_VERIFY_NONE = 0

  // Evaluate P2SH subscripts (softfork safe, BIP16).
  val SCRIPT_VERIFY_P2SH = 1 << 0

  // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
  // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
  // (softfork safe, but not used or intended as a consensus rule).
  val SCRIPT_VERIFY_STRICTENC = 1 << 1

  // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
  val SCRIPT_VERIFY_DERSIG = 1 << 2

  // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
  // (softfork safe, BIP62 rule 5).
  val SCRIPT_VERIFY_LOW_S = 1 << 3

  // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
  val SCRIPT_VERIFY_NULLDUMMY = 1 << 4

  // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
  val SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5

  // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
  // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
  // any other push causes the script to fail (BIP62 rule 3).
  // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
  // (softfork safe)
  val SCRIPT_VERIFY_MINIMALDATA = 1 << 6

  // Discourage use of NOPs reserved for upgrades (NOP1-10)
  //
  // Provided so that nodes can avoid accepting or mining transactions
  // containing executed NOP's whose meaning may change after a soft-fork,
  // thus rendering the script invalid; with this flag set executing
  // discouraged NOPs fails the script. This verification flag will never be
  // a mandatory flag applied to scripts in a block. NOPs that are not
  // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
  val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7

  // Require that only a single stack element remains after evaluation. This changes the success criterion from
  // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
  // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
  // (softfork safe, BIP62 rule 6)
  // Note: CLEANSTACK should never be used without P2SH.
  val SCRIPT_VERIFY_CLEANSTACK = 1 << 8

  // Verify CHECKLOCKTIMEVERIFY
  //
  // See BIP65 for details.
  val SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9


  // See BIP112 for details
  val SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10

  // support CHECKSEQUENCEVERIFY opcode
  //
  // Support segregated witness
  //
  val SCRIPT_VERIFY_WITNESS = 1 << 11

  // Making v2-v16 witness program non-standard
  //
  val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12


  // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
  //
  val SCRIPT_VERIFY_MINIMALIF = 1 << 13

  // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
  //
  val SCRIPT_VERIFY_NULLFAIL = 1 << 14

  // Public keys in segregated witness scripts must be compressed
  //
  val SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = 1 << 15

  // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
  //
  val SCRIPT_VERIFY_CONST_SCRIPTCODE = 1 << 16

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
  val STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE

  /** For convenience, standard but not mandatory verify flags. */
  val STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS
}

object Script {

  import Protocol._
  import ScriptFlags._
  import fr.acinq.bitcoinscala.ScriptElt._

  type Stack = List[ByteVector]

  private val True = ByteVector.fromByte(1)

  private val False = ByteVector.empty

  /**
   * parse a script from a input stream of binary data
   *
   * @param input input stream
   * @param stack initial command stack
   * @return an updated command stack
   */

  def parse(blob: ByteVector): List[ScriptElt] = parse(blob.toArray)

  def parse(blob: Array[Byte]): List[ScriptElt] = fr.acinq.bitcoin.Script.parse(blob).asScala.toList.map(kmp2scala)

  def write(script: Seq[ScriptElt]): ByteVector = ByteVector.view(fr.acinq.bitcoin.Script.write(script.map(scala2kmp).asJava))

  def isUpgradableNop(op: ScriptElt) = fr.acinq.bitcoin.Script.isUpgradableNop(op)

  def isSimpleValue(op: ScriptElt) = fr.acinq.bitcoin.Script.isSimpleValue(op)

  def simpleValue(op: ScriptElt): Byte = fr.acinq.bitcoin.Script.simpleValue(op)

  def isDisabled(op: ScriptElt) = fr.acinq.bitcoin.Script.isDisabled(op)

  def cost(op: ScriptElt): Int = fr.acinq.bitcoin.Script.cost(op)

  def encodeNumber(value: Long): ByteVector = ByteVector.view(fr.acinq.bitcoin.Script.encodeNumber(value).toByteArray)

  def decodeNumber(input: ByteVector, checkMinimalEncoding: Boolean, maximumSize: Int = 4): Long = fr.acinq.bitcoin.Script.decodeNumber(input.toArray, checkMinimalEncoding, maximumSize)

  def castToBoolean(input: ByteVector): Boolean = input.toSeq.reverse match {
    case head +: tail if head == 0x80.toByte && tail.forall(_ == 0) => false
    case something if something.exists(_ != 0) => true
    case _ => false
  }

  def isPushOnly(script: Seq[ScriptElt]): Boolean = !script.exists {
    case op if isSimpleValue(op) => false
    case OP_PUSHDATA(_, _) => false
    case _ => true
  }

  def isPayToScript(script: Seq[ScriptElt]): Boolean = script match {
    case OP_HASH160 :: OP_PUSHDATA(multisigAddress, _) :: OP_EQUAL :: Nil if multisigAddress.length == 20 => true
    case _ => false
  }

  def isPayToScript(script: ByteVector): Boolean = script.length == 23 && script(0) == elt2code(OP_HASH160).toByte && script(1) == 0x14 && script(22) == elt2code(OP_EQUAL).toByte

  def isNativeWitnessScript(script: Seq[ScriptElt]): Boolean = script match {
    case (OP_0 | OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8 | OP_9 | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16) :: OP_PUSHDATA(witnessProgram, _) :: Nil if witnessProgram.length >= 2 && witnessProgram.length <= 40 => true
    case _ => false
  }

  def isNativeWitnessScript(script: ByteVector): Boolean = isNativeWitnessScript(parse(script))

  def removeSignature(script: List[ScriptElt], signature: ByteVector): List[ScriptElt] = {
    val toRemove = OP_PUSHDATA(signature)
    script.filterNot(_ == toRemove)
  }

  def removeSignatures(script: List[ScriptElt], sigs: List[ByteVector]): List[ScriptElt] = sigs.foldLeft(script)(removeSignature)

  def checkLockTime(lockTime: Long, tx: Transaction, inputIndex: Int): Boolean = fr.acinq.bitcoin.Script.INSTANCE.checkLockTime(lockTime, tx, inputIndex)

  def checkSequence(sequence: Long, tx: Transaction, inputIndex: Int): Boolean = fr.acinq.bitcoin.Script.INSTANCE.checkSequence(sequence, tx, inputIndex)

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

  object Runner {

    /**
     * This class represents the state of the script execution engine
     *
     * @param conditions current "position" wrt if/notif/else/endif
     * @param altstack   initial alternate stack
     * @param opCount    initial op count
     * @param scriptCode initial script (can be modified by OP_CODESEPARATOR for example)
     */
    case class State(conditions: List[Boolean], altstack: Stack, opCount: Int, scriptCode: List[ScriptElt])

    type Callback = (List[ScriptElt], Stack, State) => Boolean
  }

  /**
   * Bitcoin script runner
   *
   * @param context    script execution context
   * @param scriptFlag script flags
   * @param callback   optional callback
   */
  class Runner(context: Context, scriptFlag: Int = MANDATORY_SCRIPT_VERIFY_FLAGS, callback: Option[Runner.Callback] = None) {

    private val runner = new fr.acinq.bitcoin.Script.Runner(
      new fr.acinq.bitcoin.Script.Context(context.tx, context.inputIndex, context.amount), scriptFlag, null
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
  def pay2pkh(pubKeyHash: ByteVector): Seq[ScriptElt] = {
    require(pubKeyHash.length == 20, "pubkey hash length must be 20 bytes")
    OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pubKeyHash) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil
  }

  /**
   * @param pubKey public key
   * @return a pay-to-public-key-hash script
   */
  def pay2pkh(pubKey: PublicKey): Seq[ScriptElt] = pay2pkh(pubKey.hash160)

  def isPay2pkh(script: Seq[ScriptElt]): Boolean = {
    script match {
      case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil if data.length == 20 => true
      case _ => false
    }
  }

  /**
   * @param script bitcoin script
   * @return a pay-to-script script
   */
  def pay2sh(script: Seq[ScriptElt]): Seq[ScriptElt] = pay2sh(Script.write(script))

  /**
   * @param script bitcoin script
   * @return a pay-to-script script
   */
  def pay2sh(script: ByteVector): Seq[ScriptElt] = OP_HASH160 :: OP_PUSHDATA(hash160(script)) :: OP_EQUAL :: Nil

  def isPay2sh(script: Seq[ScriptElt]): Boolean = {
    script match {
      case OP_HASH160 :: OP_PUSHDATA(data, _) :: OP_EQUAL :: Nil if data.length == 20 => true
      case _ => false
    }
  }

  /**
   * @param script bitcoin script
   * @return a pay-to-witness-script script
   */
  def pay2wsh(script: Seq[ScriptElt]): Seq[ScriptElt] = pay2wsh(Script.write(script))

  /**
   * @param script bitcoin script
   * @return a pay-to-witness-script script
   */
  def pay2wsh(script: ByteVector): Seq[ScriptElt] = OP_0 :: OP_PUSHDATA(sha256(script)) :: Nil

  def isPay2wsh(script: Seq[ScriptElt]): Boolean = {
    script match {
      case OP_0 :: OP_PUSHDATA(data, _) :: Nil if data.length == 32 => true
      case _ => false
    }
  }

  /**
   * @param pubKeyHash public key hash
   * @return a pay-to-witness-public-key-hash script
   */
  def pay2wpkh(pubKeyHash: ByteVector): Seq[ScriptElt] = {
    require(pubKeyHash.length == 20, "pubkey hash length must be 20 bytes")
    OP_0 :: OP_PUSHDATA(pubKeyHash) :: Nil
  }

  /**
   * @param pubKey public key
   * @return a pay-to-witness-public-key-hash script
   */
  def pay2wpkh(pubKey: PublicKey): Seq[ScriptElt] = pay2wpkh(pubKey.hash160)

  def isPay2wpkh(script: Seq[ScriptElt]): Boolean = {
    script match {
      case OP_0 :: OP_PUSHDATA(data, _) :: Nil if data.length == 20 => true
      case _ => false
    }
  }

  /**
   * @param pubKey public key
   * @param sig    signature matching the public key
   * @return script witness for the corresponding pay-to-witness-public-key-hash script
   */
  def witnessPay2wpkh(pubKey: PublicKey, sig: ByteVector): ScriptWitness = ScriptWitness(sig :: pubKey.value :: Nil)

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
