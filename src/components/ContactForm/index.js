import React from "react"
import { navigateTo } from "gatsby-link"
import NetlifyForm from "react-netlify-form"

import Button from "../Button"
import "./styles.scss"

function encode(data) {
  return Object.keys(data)
    .map(key => encodeURIComponent(key) + "=" + encodeURIComponent(data[key]))
    .join("&")
}

export default class ContactForm extends React.Component {
  constructor(props) {
    super(props)
    this.state = {}
  }

  handleChange = e => {
    this.setState({ [e.target.name]: e.target.value })
  }

  handleRecaptcha = value => {
    this.setState({ "g-recaptcha-response": value })
  }

  handleSubmit = e => {
    e.preventDefault()
    const form = e.target
    fetch("/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: encode({
        "form-name": form.getAttribute("name"),
        ...this.state,
      }),
    }).catch(error => alert(error))
  }

  render() {
    return (
      <div className="contact-form__container">
        <NetlifyForm name="Contact Form">
          {({ loading, error, success }) => (
            <div>
              {/* {error && (
                <div>
                  Your information was not sent. Please try again later.
                </div>
              )} */}
              {success && (
                <>
                  <div className="contact-form__top">Lähetä viesti</div>
                  <p>
                    <label>
                      Nimesi (pakollinen)
                      <br />
                      <input
                        type="text"
                        name="name"
                        disabled
                        className="contact-form__input"
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Sähköposti (pakollinen)
                      <br />
                      <input
                        type="email"
                        name="email"
                        disabled
                        className="contact-form__input"
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Viestisi
                      <br />
                      <textarea
                        className="contact-form__textarea"
                        rows="9"
                        disabled
                      />
                    </label>
                  </p>

                  <div>
                    <Button
                      variant="orange"
                      size="md"
                      label="Kiitos Paljon!"
                      disabled
                    />
                  </div>
                </>
              )}
              {!loading && !success && (
                <>
                  <div className="contact-form__top">Lähetä viesti</div>
                  <p>
                    <label>
                      Nimesi (pakollinen)
                      <br />
                      <input
                        type="text"
                        name="name"
                        className="contact-form__input"
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Sähköposti (pakollinen)
                      <br />
                      <input
                        type="email"
                        name="email"
                        onChange={this.handleChange}
                        className="contact-form__input"
                      />
                    </label>
                  </p>
                  <p>
                    <label>
                      Viestisi
                      <br />
                      <textarea
                        name="message"
                        onChange={this.handleChange}
                        className="contact-form__textarea"
                        rows="9"
                      />
                    </label>
                  </p>

                  <div>
                    <Button variant="orange" size="md" label="Lähetä" />
                  </div>
                </>
              )}
            </div>
          )}
        </NetlifyForm>
      </div>
    )
  }
}
