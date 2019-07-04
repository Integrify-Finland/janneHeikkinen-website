import React from "react"

import "./styles.scss"
import kokoomusLogo from "./assets/kokoomus-logo.svg"
import FacebookIcon from "../SocialMediaIcons/Facebook/index"
import TwitterIcon from "../SocialMediaIcons/Twitter/index"
import InstagramIcon from "../SocialMediaIcons/Instagram/index"
import LinkedInIcon from "../SocialMediaIcons/Linkedin/index"
import YouTubeIcon from "../SocialMediaIcons/Youtube/index"

const Footer = () => {
  const year = new Date().getFullYear()

  const copyright = `Copyright ${String.fromCharCode(
    169
  )} ${year} Janne Heikkinen`

  return (
    <div className="footer">
      <div className="left-box">
        <div className="social-media">
          <a href="#" target="blank" rel="noopener" title="Go to Facebook">
            <FacebookIcon iconSize="big" />
          </a>

          <a href="#" target="blank" rel="noopener" title="Go to Twitter">
            <TwitterIcon iconSize="big" />
          </a>

          <a href="#" target="blank" rel="noopener" title="Go to Instagram">
            <InstagramIcon iconSize="big" />
          </a>

          <a href="#" target="blank" rel="noopener" title="Go to LinkedIn">
            <LinkedInIcon iconSize="big" />
          </a>

          {
            <a href="#" target="blank" rel="noopener" title="Go to YouTube">
              <YouTubeIcon iconSize="big" />
            </a>
          }
        </div>

        <div className="contact-container">
          <div className="contact-container__contact1">
            <h1>Janne Heikkinen</h1>
            <p>
              Kansanedustaja <br />
              Puhelin:
              <br />
              +358 (0) 40 5554263
              <br />
              Sähköposti:
              <br />
              janne.heikkinen (at) eduskunta.fi
            </p>
          </div>

          <div className="contact-container__contact2">
            <h1>Mikko Laakso</h1>
            <p>
              Kansanedustajan avustaja
              <br />
              Puhelin:
              <br />
              +358 (0) 50 383 9432
              <br />
              Sähköposti:
              <br />
              mikko.laakso (at) eduskunta.fi
            </p>
          </div>
        </div>

        <p className="copyright">{copyright}</p>
      </div>

      <div className="logo-container">
        <img src={kokoomusLogo} alt="Kokoomus Logo" />
      </div>
    </div>
  )
}

export default Footer
