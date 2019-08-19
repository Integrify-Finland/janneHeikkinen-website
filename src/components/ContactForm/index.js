import React from "react"
import { navigateTo } from "gatsby-link"
import NetlifyForm from "react-netlify-form"

import Button from "../Button"
import "./styles.scss"

const ContactForm = () => {
  const renderDisabledForm = msg => {
    return (
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
            <textarea className="contact-form__textarea" rows="9" disabled />
          </label>
        </p>

        <div>
          <Button variant="orange" size="md" label={msg} disabled />
        </div>
      </>
    )
  }
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
            {loading && renderDisabledForm("Ladataan")}
            {success && renderDisabledForm("Kiitos Paljon!")}
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

export default ContactForm
