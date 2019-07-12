import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"

const Yhteys = ({ data }) => {
  const { contactUs } = data

  return (
    <Layout>
      <SEO title="Yhteys" />
    </Layout>
  )
}

export default Yhteys

export const query = graphql`
  query {
    contactUs: allContentfulContactUs {
      edges {
        node {
          name
          title
          phoneNumber
          email
        }
      }
    }
  }
`
