from TracingAutonomousSystems.tracing import TracingAutonomousSystems


if __name__ == '__main__':
    print("Введите доменное имя или IP адрес")
    domen = str(input())
    tr = TracingAutonomousSystems(domen)
    tr.run()

