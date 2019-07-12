import React from "react"
import PropTypes from "prop-types"
import { useStaticQuery, graphql } from "gatsby"

import Footer from "../Footer"
import Header from "../Header"
import Section from "../Section"

const Layout = ({ children }) => {
  const data = useStaticQuery(graphql`
    query SiteTitleQuery {
      site {
        siteMetadata {
          title
        }
      }
    }
  `)

  return (
    <>
      {/* <Header siteTitle={data.site.siteMetadata.title} /> */}

      <Section>
        <main>{children}</main>
      </Section>

      <Footer
        firstPersonName="Janne Heikkinen"
        firstPersonTitle="Kansanedustaja"
        firstPersonPhone="+358 (0) 40 5554263"
        firstPersonEmail="janne.heikkinen (at) eduskunta.fi"
        secondPersonName="Mikko Laakso"
        secondPersonTitle="Kansanedustajan avustaja"
        secondPersonPhone="+358 (0) 50 383 9432"
        secondPersonEmail="mikko.laakso (at) eduskunta.fi"
      />
    </>
  )
}

Layout.propTypes = {
  children: PropTypes.node.isRequired,
}

export default Layout
