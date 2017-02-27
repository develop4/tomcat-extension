package uk.co.develop4.security.codecs;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  TestNullCodec.class,
  TestHexCodec.class,
  TestRSASealedCodecService.class
})

public class CodecTestSuite {

}
