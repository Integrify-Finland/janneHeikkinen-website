import React from "react"
import PropTypes from "prop-types"
import { useStaticQuery, graphql } from "gatsby"

import Footer from "../Footer"

import Navigation from "../Navigation"

const Layout = ({ children }) => {
  const data = useStaticQuery(graphql`
    query SiteTitleQuery {
      contactUs: allContentfulContactUs(sort: { fields: order, order: ASC }) {
        edges {
          node {
            name
            title
            phoneNumber
            email
            order
          }
        }
      }
    }
  `)

  return (
    <>
      <Navigation />
      <main>{children}</main>

      <Footer contactUs={data.contactUs.edges} />
    </>
  )
}

Layout.propTypes = {
  children: PropTypes.node.isRequired,
}

export default Layout
