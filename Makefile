.PHONY: up down logs demo

up:
\tdocker compose up --build -d

logs:
\tdocker compose logs -f auth resource

down:
\tdocker compose down

demo:
\bash script/pcke_demo.sh