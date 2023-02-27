import React from "react"
import PropTypes from "prop-types"

import "./styles.scss"
import kokoomusLogo from "./assets/kokoomus-logo.svg"
import FacebookIcon from "../SocialMediaIcons/Facebook/index"
import TwitterIcon from "../SocialMediaIcons/Twitter/index"
import InstagramIcon from "../SocialMediaIcons/Instagram/index"
import LinkedInIcon from "../SocialMediaIcons/Linkedin"

const Footer = ({ contactUs }) => {
  const year = new Date().getFullYear()

  const copyright = `Copyright ${String.fromCharCode(
    169
  )} ${year} Janne Heikkinen`

  return (
    <div className="footer">
      <div className="footer__left-box">
        <div className="footer__social-media">
          <a
            href="https://www.facebook.com/janneheikkinenpage/"
            target="blank"
            rel="noopener"
            title="Go to Facebook"
          >
            <FacebookIcon iconSize="big" />
          </a>

          <a
            href="https://twitter.com/heikkinenjanne"
            target="blank"
            rel="noopener"
            title="Go to Twitter"
          >
            <TwitterIcon iconSize="big" />
          </a>
          <a
            href="https://www.linkedin.com/in/janne-heikkinen-5a6a9562/"
            target="blank"
            rel="noopener"
            title="Go to Janne's LinkedIn profile"
          >
            <LinkedInIcon iconSize="big" />
          </a>
          <a
            href="https://www.instagram.com/janneheikkinen/"
            target="blank"
            rel="noopener"
            title="Go to Instagram"
          >
            <InstagramIcon iconSize="big" />
          </a>
        </div>

        <div className="footer__contact-container">
          {contactUs.map(({ node }) => (
            <div className="footer__contact1" key={node.name}>
              <h1>{node.name}</h1>
              <p>
                {node.title} <br />
                Puhelin:
                <br />
                {node.phoneNumber}
                <br />
                Sähköposti:
                <br />
                {node.email}
              </p>
            </div>
          ))}
        </div>

        <p className="footer__copyright">{copyright}</p>
      </div>

      <div className="footer__logo-container">
        <img src={kokoomusLogo} alt="Kokoomus Logo" />
      </div>
    </div>
  )
}

Footer.propTypes = {
  firstPersonName: PropTypes.string,
  secondPersonName: PropTypes.string,
  firstPersonTitle: PropTypes.string,
  secondPersonTitle: PropTypes.string,
  firstPersonPhone: PropTypes.string,
  secondPersonPhone: PropTypes.string,
  firstPersonEmail: PropTypes.string,
  secondPersonEmail: PropTypes.string,
}

export default Footer
