package fr.acinq.bitcoinscala

import fr.acinq.bitcoinscala.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin
import scodec.bits.ByteVector

import java.io.{InputStream, OutputStream}
import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

object KotlinUtils {
  implicit def kmp2scala(input: fr.acinq.bitcoin.ByteVector32): ByteVector32 = ByteVector32(ByteVector(input.toByteArray))

  implicit def scala2kmp(input: ByteVector32) = new bitcoin.ByteVector32(input.toArray)

  implicit def kmp2scala(input: fr.acinq.bitcoin.ByteVector64): ByteVector64 = ByteVector64(ByteVector(input.toByteArray))

  implicit def scala2kmp(input: ByteVector64) = new bitcoin.ByteVector64(input.toArray)

  implicit def kmp2scala(input: fr.acinq.bitcoin.ByteVector): ByteVector = ByteVector(input.toByteArray)

  implicit def scala2kmp(input: ByteVector) = new bitcoin.ByteVector(input.toArray)

  implicit def kmp2scala(input: fr.acinq.bitcoin.OutPoint): OutPoint = OutPoint(input.hash, input.index)

  implicit def scala2kmp(input: OutPoint): bitcoin.OutPoint = new bitcoin.OutPoint(input.hash, input.index)

  implicit def kmp2scala(input: fr.acinq.bitcoin.ScriptWitness): ScriptWitness = ScriptWitness(input.stack.asScala.toList.map(kmp2scala))

  implicit def scala2kmp(input: ScriptWitness): bitcoin.ScriptWitness = new bitcoin.ScriptWitness(input.stack.map(scala2kmp).asJava)

  implicit def kmp2scala(input: fr.acinq.bitcoin.TxIn): TxIn = TxIn(input.outPoint, input.signatureScript, input.sequence, input.witness)

  implicit def scala2kmp(input: Satoshi): bitcoin.Satoshi = new bitcoin.Satoshi(input.toLong)

  implicit def kmp2scala(input: fr.acinq.bitcoin.Satoshi): Satoshi = Satoshi(input.toLong)

  implicit def scala2kmp(input: TxIn): bitcoin.TxIn = new bitcoin.TxIn(scala2kmp(input.outPoint), input.signatureScript, input.sequence, scala2kmp(input.witness))

  implicit def kmp2scala(input: fr.acinq.bitcoin.TxOut): TxOut = TxOut(input.amount, input.publicKeyScript)

  implicit def scala2kmp(input: TxOut): bitcoin.TxOut = new bitcoin.TxOut(input.amount, input.publicKeyScript)

  implicit def kmp2scala(input: fr.acinq.bitcoin.Transaction): Transaction = Transaction(input.version, input.txIn.asScala.toList.map(kmp2scala), input.txOut.asScala.toList.map(kmp2scala), input.lockTime)

  implicit def scala2kmp(input: Transaction): bitcoin.Transaction = new bitcoin.Transaction(input.version, input.txIn.map(scala2kmp).asJava, input.txOut.map(scala2kmp).asJava, input.lockTime)

  implicit def kmp2scala(input: fr.acinq.bitcoin.PrivateKey): PrivateKey = PrivateKey(input)

  implicit def scala2kmp(input: PrivateKey): bitcoin.PrivateKey = new bitcoin.PrivateKey(input.value)

  implicit def kmp2scala(input: fr.acinq.bitcoin.PublicKey): PublicKey = PublicKey(input)

  implicit def scala2kmp(input: PublicKey): bitcoin.PublicKey = new bitcoin.PublicKey(input.value)

  case class InputStreamWrapper(is: InputStream) extends fr.acinq.bitcoin.io.Input {
    override def getAvailableBytes: Int = is.available()

    override def read(): Int = is.read()

    override def read(bytes: Array[Byte], i: Int, i1: Int): Int = is.read(bytes, i, i1)
  }

  case class OutputStreamWrapper(os: OutputStream) extends fr.acinq.bitcoin.io.Output {
    override def write(bytes: Array[Byte], i: Int, i1: Int): Unit = os.write(bytes, i, i1)

    override def write(i: Int): Unit = os.write(i)
  }

  implicit def scala2kmp(input: ScriptElt): fr.acinq.bitcoin.ScriptElt = input match {
    case OP_PUSHDATA(data, _) => new bitcoin.OP_PUSHDATA(data)
    case _ => scriptEltMapScala2Kmp(input)
  }

  implicit def kmp2scala(input: fr.acinq.bitcoin.ScriptElt): ScriptElt = input match {
    case oppushdata: bitcoin.OP_PUSHDATA => OP_PUSHDATA(oppushdata.data, oppushdata.code)
    case _ => scriptEltMapKmp2Scala2Map(input)
  }

  private val scriptEltMapScala2Kmp: Map[ScriptElt, fr.acinq.bitcoin.ScriptElt] = Map(
    OP_0 -> fr.acinq.bitcoin.OP_0.INSTANCE,    OP_1NEGATE -> fr.acinq.bitcoin.OP_1NEGATE.INSTANCE,
    OP_RESERVED -> fr.acinq.bitcoin.OP_RESERVED.INSTANCE,
    OP_1 -> fr.acinq.bitcoin.OP_1.INSTANCE,
    OP_2 -> fr.acinq.bitcoin.OP_2.INSTANCE,
    OP_3 -> fr.acinq.bitcoin.OP_3.INSTANCE,
    OP_4 -> fr.acinq.bitcoin.OP_4.INSTANCE,
    OP_5 -> fr.acinq.bitcoin.OP_5.INSTANCE,
    OP_6 -> fr.acinq.bitcoin.OP_6.INSTANCE,
    OP_7 -> fr.acinq.bitcoin.OP_7.INSTANCE,
    OP_8 -> fr.acinq.bitcoin.OP_8.INSTANCE,
    OP_9 -> fr.acinq.bitcoin.OP_9.INSTANCE,
    OP_10 -> fr.acinq.bitcoin.OP_10.INSTANCE,
    OP_11 -> fr.acinq.bitcoin.OP_11.INSTANCE,
    OP_12 -> fr.acinq.bitcoin.OP_12.INSTANCE,
    OP_13 -> fr.acinq.bitcoin.OP_13.INSTANCE,
    OP_14 -> fr.acinq.bitcoin.OP_14.INSTANCE,
    OP_15 -> fr.acinq.bitcoin.OP_15.INSTANCE,
    OP_16 -> fr.acinq.bitcoin.OP_16.INSTANCE,
    OP_NOP -> fr.acinq.bitcoin.OP_NOP.INSTANCE,
    OP_VER -> fr.acinq.bitcoin.OP_VER.INSTANCE,
    OP_IF -> fr.acinq.bitcoin.OP_IF.INSTANCE,
    OP_NOTIF -> fr.acinq.bitcoin.OP_NOTIF.INSTANCE,
    OP_VERIF -> fr.acinq.bitcoin.OP_VERIF.INSTANCE,
    OP_VERNOTIF -> fr.acinq.bitcoin.OP_VERNOTIF.INSTANCE,
    OP_ELSE -> fr.acinq.bitcoin.OP_ELSE.INSTANCE,
    OP_ENDIF -> fr.acinq.bitcoin.OP_ENDIF.INSTANCE,
    OP_VERIFY -> fr.acinq.bitcoin.OP_VERIFY.INSTANCE,
    OP_RETURN -> fr.acinq.bitcoin.OP_RETURN.INSTANCE,
    OP_TOALTSTACK -> fr.acinq.bitcoin.OP_TOALTSTACK.INSTANCE,
    OP_FROMALTSTACK -> fr.acinq.bitcoin.OP_FROMALTSTACK.INSTANCE,
    OP_2DROP -> fr.acinq.bitcoin.OP_2DROP.INSTANCE,
    OP_2DUP -> fr.acinq.bitcoin.OP_2DUP.INSTANCE,
    OP_3DUP -> fr.acinq.bitcoin.OP_3DUP.INSTANCE,
    OP_2OVER -> fr.acinq.bitcoin.OP_2OVER.INSTANCE,
    OP_2ROT -> fr.acinq.bitcoin.OP_2ROT.INSTANCE,
    OP_2SWAP -> fr.acinq.bitcoin.OP_2SWAP.INSTANCE,
    OP_IFDUP -> fr.acinq.bitcoin.OP_IFDUP.INSTANCE,
    OP_DEPTH -> fr.acinq.bitcoin.OP_DEPTH.INSTANCE,
    OP_DROP -> fr.acinq.bitcoin.OP_DROP.INSTANCE,
    OP_DUP -> fr.acinq.bitcoin.OP_DUP.INSTANCE,
    OP_NIP -> fr.acinq.bitcoin.OP_NIP.INSTANCE,
    OP_OVER -> fr.acinq.bitcoin.OP_OVER.INSTANCE,
    OP_PICK -> fr.acinq.bitcoin.OP_PICK.INSTANCE,
    OP_ROLL -> fr.acinq.bitcoin.OP_ROLL.INSTANCE,
    OP_ROT -> fr.acinq.bitcoin.OP_ROT.INSTANCE,
    OP_SWAP -> fr.acinq.bitcoin.OP_SWAP.INSTANCE,
    OP_TUCK -> fr.acinq.bitcoin.OP_TUCK.INSTANCE,
    OP_CAT -> fr.acinq.bitcoin.OP_CAT.INSTANCE,
    OP_SUBSTR -> fr.acinq.bitcoin.OP_SUBSTR.INSTANCE,
    OP_LEFT -> fr.acinq.bitcoin.OP_LEFT.INSTANCE,
    OP_RIGHT -> fr.acinq.bitcoin.OP_RIGHT.INSTANCE,
    OP_SIZE -> fr.acinq.bitcoin.OP_SIZE.INSTANCE,
    OP_INVERT -> fr.acinq.bitcoin.OP_INVERT.INSTANCE,
    OP_AND -> fr.acinq.bitcoin.OP_AND.INSTANCE,
    OP_OR -> fr.acinq.bitcoin.OP_OR.INSTANCE,
    OP_XOR -> fr.acinq.bitcoin.OP_XOR.INSTANCE,
    OP_EQUAL -> fr.acinq.bitcoin.OP_EQUAL.INSTANCE,
    OP_EQUALVERIFY -> fr.acinq.bitcoin.OP_EQUALVERIFY.INSTANCE,
    OP_RESERVED1 -> fr.acinq.bitcoin.OP_RESERVED1.INSTANCE,
    OP_RESERVED2 -> fr.acinq.bitcoin.OP_RESERVED2.INSTANCE,
    OP_1ADD -> fr.acinq.bitcoin.OP_1ADD.INSTANCE,
    OP_1SUB -> fr.acinq.bitcoin.OP_1SUB.INSTANCE,
    OP_2MUL -> fr.acinq.bitcoin.OP_2MUL.INSTANCE,
    OP_2DIV -> fr.acinq.bitcoin.OP_2DIV.INSTANCE,
    OP_NEGATE -> fr.acinq.bitcoin.OP_NEGATE.INSTANCE,
    OP_ABS -> fr.acinq.bitcoin.OP_ABS.INSTANCE,
    OP_NOT -> fr.acinq.bitcoin.OP_NOT.INSTANCE,
    OP_0NOTEQUAL -> fr.acinq.bitcoin.OP_0NOTEQUAL.INSTANCE,
    OP_ADD -> fr.acinq.bitcoin.OP_ADD.INSTANCE,
    OP_SUB -> fr.acinq.bitcoin.OP_SUB.INSTANCE,
    OP_MUL -> fr.acinq.bitcoin.OP_MUL.INSTANCE,
    OP_DIV -> fr.acinq.bitcoin.OP_DIV.INSTANCE,
    OP_MOD -> fr.acinq.bitcoin.OP_MOD.INSTANCE,
    OP_LSHIFT -> fr.acinq.bitcoin.OP_LSHIFT.INSTANCE,
    OP_RSHIFT -> fr.acinq.bitcoin.OP_RSHIFT.INSTANCE,
    OP_BOOLAND -> fr.acinq.bitcoin.OP_BOOLAND.INSTANCE,
    OP_BOOLOR -> fr.acinq.bitcoin.OP_BOOLOR.INSTANCE,
    OP_NUMEQUAL -> fr.acinq.bitcoin.OP_NUMEQUAL.INSTANCE,
    OP_NUMEQUALVERIFY -> fr.acinq.bitcoin.OP_NUMEQUALVERIFY.INSTANCE,
    OP_NUMNOTEQUAL -> fr.acinq.bitcoin.OP_NUMNOTEQUAL.INSTANCE,
    OP_LESSTHAN -> fr.acinq.bitcoin.OP_LESSTHAN.INSTANCE,
    OP_GREATERTHAN -> fr.acinq.bitcoin.OP_GREATERTHAN.INSTANCE,
    OP_LESSTHANOREQUAL -> fr.acinq.bitcoin.OP_LESSTHANOREQUAL.INSTANCE,
    OP_GREATERTHANOREQUAL -> fr.acinq.bitcoin.OP_GREATERTHANOREQUAL.INSTANCE,
    OP_MIN -> fr.acinq.bitcoin.OP_MIN.INSTANCE,
    OP_MAX -> fr.acinq.bitcoin.OP_MAX.INSTANCE,
    OP_WITHIN -> fr.acinq.bitcoin.OP_WITHIN.INSTANCE,
    OP_RIPEMD160 -> fr.acinq.bitcoin.OP_RIPEMD160.INSTANCE,
    OP_SHA1 -> fr.acinq.bitcoin.OP_SHA1.INSTANCE,
    OP_SHA256 -> fr.acinq.bitcoin.OP_SHA256.INSTANCE,
    OP_HASH160 -> fr.acinq.bitcoin.OP_HASH160.INSTANCE,
    OP_HASH256 -> fr.acinq.bitcoin.OP_HASH256.INSTANCE,
    OP_CODESEPARATOR -> fr.acinq.bitcoin.OP_CODESEPARATOR.INSTANCE,
    OP_CHECKSIG -> fr.acinq.bitcoin.OP_CHECKSIG.INSTANCE,
    OP_CHECKSIGVERIFY -> fr.acinq.bitcoin.OP_CHECKSIGVERIFY.INSTANCE,
    OP_CHECKMULTISIG -> fr.acinq.bitcoin.OP_CHECKMULTISIG.INSTANCE,
    OP_CHECKMULTISIGVERIFY -> fr.acinq.bitcoin.OP_CHECKMULTISIGVERIFY.INSTANCE,
    OP_NOP1 -> fr.acinq.bitcoin.OP_NOP1.INSTANCE,
    OP_CHECKLOCKTIMEVERIFY -> fr.acinq.bitcoin.OP_CHECKLOCKTIMEVERIFY.INSTANCE,
    OP_CHECKSEQUENCEVERIFY -> fr.acinq.bitcoin.OP_CHECKSEQUENCEVERIFY.INSTANCE,
    OP_NOP4 -> fr.acinq.bitcoin.OP_NOP4.INSTANCE,
    OP_NOP5 -> fr.acinq.bitcoin.OP_NOP5.INSTANCE,
    OP_NOP6 -> fr.acinq.bitcoin.OP_NOP6.INSTANCE,
    OP_NOP7 -> fr.acinq.bitcoin.OP_NOP7.INSTANCE,
    OP_NOP8 -> fr.acinq.bitcoin.OP_NOP8.INSTANCE,
    OP_NOP9 -> fr.acinq.bitcoin.OP_NOP9.INSTANCE,
    OP_NOP10 -> fr.acinq.bitcoin.OP_NOP10.INSTANCE,
    OP_SMALLINTEGER -> fr.acinq.bitcoin.OP_SMALLINTEGER.INSTANCE,
    OP_INVALIDOPCODE -> fr.acinq.bitcoin.OP_INVALIDOPCODE.INSTANCE)

  private val scriptEltMapKmp2Scala2Map: Map[fr.acinq.bitcoin.ScriptElt, ScriptElt] = scriptEltMapScala2Kmp.map { case (k,v) => v -> k }.toMap
}
