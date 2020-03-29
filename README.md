THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# ctap

ctap is a library implementing the [FIDO2 CTAP](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html) protocol.

## Usage example

```rust
use ctap_hmac::*;
let device_info = get_devices()?.next().expect("no device connected");
let mut device = FidoDevice::new(&device_info)?;

// This can be omitted if the FIDO device is not configured with a PIN.
let pin = "test";
device.unlock(pin)?;

// In a real application these values would come from the requesting app.
let cred_request = FidoCredentialRequestBuilder::default()
                    .rp_id("rp_id")
                    .user_name("user_name")
                    .build().unwrap();

let cred = device.make_credential(&cred_request)?;
let cred = &&cred;
let assertion_request = FidoAssertionRequestBuilder::default()
                            .rp_id("rp_id")
                            .credential(&&cred)
                            .build().unwrap();
// In a real application the credential would be stored and used later.
let result = device.get_assertion(&assertion_request);
```

## Limitations

Currently, this library only supports Linux. Testing and contributions for
other platforms is welcome.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
