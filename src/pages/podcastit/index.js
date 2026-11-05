import React from "react"
import { graphql } from "gatsby"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import Section from "../../components/Section"

import "./styles.scss"

const Podcastit = ({ data }) => {
  const podcasts = data.podcasts.edges

  return (
    <Layout>
      <SEO title="Podcastit" />
      <Section>
        <div className="podcastit">
          <h1 className="podcastit__title">Podcastit</h1>
          {podcasts.length === 0 ? (
            <p className="podcastit__empty">Podcasteja ei ole vielä lisätty.</p>
          ) : (
            <ul className="podcastit__list">
              {podcasts.map(({ node }) => (
                <li className="podcastit__item" key={node.id}>
                  <div className="podcastit__info">
                    <h2 className="podcastit__topic">{node.topic}</h2>
                    <p className="podcastit__meta">
                      {node.podcastName}
                      {node.host && ` / ${node.host}`}
                    </p>
                    <time className="podcastit__date" dateTime={node.isoDate}>
                      {node.date}
                    </time>
                  </div>
                  <a
                    className="podcastit__link"
                    href={node.url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Kuuntele
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>
    </Layout>
  )
}

export default Podcastit

export const query = graphql`
  query {
    podcasts: allContentfulPodcast(sort: { fields: [date], order: DESC }) {
      edges {
        node {
          id
          topic
          podcastName
          host
          url
          date(formatString: "D.M.YYYY")
          isoDate: date(formatString: "YYYY-MM-DD")
        }
      }
    }
  }
`
