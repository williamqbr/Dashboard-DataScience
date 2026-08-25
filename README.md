# Dashboard de Cybersegurança em Streamlit

Este projeto foi adaptado para atender ao documento solicitado, com dashboard profissional em segurança cibernética e abas adicionais sobre apresentação profissional, qualificações e skills.

## Como executar

1. Acesse a pasta do projeto.
2. Instale as dependências:
   pip install -r requirements.txt
3. Execute:
   streamlit run app.py
4. Abra no navegador:
   http://localhost:8501

## Estrutura

- `app.py` — aplicação principal em Streamlit
- `cyber_dashboard.db` — banco SQLite gerado automaticamente
- `requirements.txt` — dependências do projeto

## Abas incluídas

- Dashboard de segurança operacional
- Quem sou eu
- Minhas qualificações
- Skills

## Dados

O banco é preenchido com registros sintéticos de incidentes de segurança, incluindo:

- tipo de ameaça
- vetor de ataque
- severidade
- região
- setor
- custo, tempo de resposta e ativos afetados

## Recursos

- filtros por setor, severidade e região
- KPIs operacionais
- gráficos de tendências e distribuição
- visualização de eventos recentes
- seção profissional com formação, experiência e competências
